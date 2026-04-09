<?php
session_start();
ini_set('display_errors', 1);
error_reporting(E_ALL);

// [핵심 수정] 기존 코드에서 호출만 하고 정의되지 않았던 CSRF 함수 추가
if (!function_exists('csrf_token')) {
    function csrf_token() {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
}

$conn = new mysqli("localhost", "root", "", "travel_db");
if ($conn->connect_error) { die("DB 연결 실패: " . $conn->connect_error); }
$conn->set_charset("utf8mb4");

// [DB 초기화] 테이블 생성 및 기존 데이터 구조 보존을 위한 컬럼 체크
$conn->query("CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY, 
    username VARCHAR(50) UNIQUE,
    name VARCHAR(100),
    email VARCHAR(150) UNIQUE,
    phone VARCHAR(30),
    password VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)");

// 기존 테이블에 누락된 컬럼 자동 추가 (기존 기능 유지용)
$check_cols = [
    'users' => ['name' => 'VARCHAR(100)', 'email' => 'VARCHAR(150) UNIQUE', 'phone' => 'VARCHAR(30)'],
    'trips' => ['return_flight_time' => 'DATETIME', 'return_flight_price' => 'INT DEFAULT 0', 'trip_type' => "VARCHAR(10) DEFAULT 'roundtrip'", 'airline' => 'VARCHAR(100)'],
    'expenses' => ['my_share_krw' => 'INT DEFAULT 0', 'paid_by' => 'VARCHAR(100)', 'participants' => 'INT DEFAULT 1']
];

foreach ($check_cols as $table => $cols) {
    foreach ($cols as $col => $def) {
        $res = $conn->query("SHOW COLUMNS FROM $table LIKE '$col'");
        if ($res->num_rows == 0) { $conn->query("ALTER TABLE $table ADD COLUMN $col $def"); }
    }
}

// 나머지 테이블 생성 (trips, expenses) - 기존 구조와 동일
$conn->query("CREATE TABLE IF NOT EXISTS trips (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, title VARCHAR(255), country VARCHAR(10), currency VARCHAR(10), trip_type VARCHAR(10) DEFAULT 'roundtrip', airline VARCHAR(100), flight_time DATETIME, return_flight_time DATETIME, flight_price INT DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
$conn->query("CREATE TABLE IF NOT EXISTS expenses (id INT AUTO_INCREMENT PRIMARY KEY, trip_id INT, user_id INT, category VARCHAR(50), description VARCHAR(255), amount_foreign DECIMAL(15,2), amount_krw INT, my_share_krw INT DEFAULT 0, paid_by VARCHAR(100), participants INT DEFAULT 1, currency VARCHAR(10), expense_date DATE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");

$error = ''; $success = '';

// 공통 헬퍼 함수
function e(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
function isValidPassword($pw) { return preg_match('/^(?=.*[A-Za-z])(?=.*\\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:\\|,.<>\/?]).{8,20}$/', $pw); }
function isValidPhone($p) { return preg_match('/^01[016789]-?\\d{3,4}-?\\d{4}$/', $p); }
function isValidUsername($u) { return preg_match('/^[A-Za-z0-9_]{4,20}$/', $u); }

// [회원가입/로그인/로그아웃 로직] - 처음 코드의 모든 유효성 검사 포함
if (isset($_POST['register'])) {
    $name = trim($_POST['reg_name'] ?? '');
    $user = trim($_POST['reg_username'] ?? '');
    $email = trim($_POST['reg_email'] ?? '');
    $phone = trim($_POST['reg_phone'] ?? '');
    $pw = $_POST['reg_password'] ?? '';
    if (!isValidUsername($user)) $error = '아이디 형식이 맞지 않습니다.';
    elseif (!isValidPassword($pw)) $error = '비밀번호는 영문, 숫자, 특수문자 포함 8~20자여야 합니다.';
    elseif ($pw !== $_POST['reg_password_confirm']) $error = '비밀번호가 일치하지 않습니다.';
    else {
        $hpw = password_hash($pw, PASSWORD_DEFAULT);
        try {
            $conn->query("INSERT INTO users (username, name, email, phone, password) VALUES ('$user', '$name', '$email', '$phone', '$hpw')");
            $success = '가입 완료! 로그인하세요.';
        } catch (Exception $e) { $error = '중복된 아이디 또는 이메일입니다.'; }
    }
}

if (isset($_POST['login'])) {
    $lid = $conn->real_escape_string($_POST['login_id']);
    $res = $conn->query("SELECT * FROM users WHERE username='$lid' OR email='$lid'");
    $u = $res->fetch_assoc();
    if ($u && password_verify($_POST['password'], $u['password'])) {
        $_SESSION['user_id'] = $u['id'];
        $_SESSION['user'] = $u['username'];
        $_SESSION['user_name'] = $u['name'] ?: $u['username'];
        $_SESSION['user_email'] = $u['email'];
    } else { $error = '정보가 일치하지 않습니다.'; }
}

if (isset($_GET['logout'])) { session_destroy(); header("Location: ?"); exit; }

// [프로필 업데이트] - 현재 비밀번호 확인 로직 포함
if (isset($_POST['update_profile'])) {
    $uid = $_SESSION['user_id'];
    $name = trim($_POST['profile_name']);
    $email = trim($_POST['profile_email']);
    $new_pw = $_POST['new_password'];
    
    $u_res = $conn->query("SELECT password FROM users WHERE id=$uid");
    $u_data = $u_res->fetch_assoc();

    if ($new_pw !== '' && !password_verify($_POST['current_password'], $u_data['password'])) {
        $error = '현재 비밀번호가 틀렸습니다.';
    } else {
        if ($new_pw !== '') {
            $hpw = password_hash($new_pw, PASSWORD_DEFAULT);
            $conn->query("UPDATE users SET name='$name', email='$email', password='$hpw' WHERE id=$uid");
        } else {
            $conn->query("UPDATE users SET name='$name', email='$email' WHERE id=$uid");
        }
        $_SESSION['user_name'] = $name;
        $success = '프로필이 수정되었습니다.';
    }
}

// [여행 및 지출 저장] - 왕복/편도, N빵 계산 기능 포함
if (isset($_POST['save_trip'])) {
    $uid = $_SESSION['user_id'];
    $title = $conn->real_escape_string($_POST['trip_title']);
    $type = $_POST['trip_type'];
    $f_time = !empty($_POST['flight_time']) ? "'".$_POST['flight_time']."'" : "NULL";
    $r_time = ($type === 'roundtrip' && !empty($_POST['return_flight_time'])) ? "'".$_POST['return_flight_time']."'" : "NULL";
    $conn->query("INSERT INTO trips (user_id, title, country, currency, trip_type, airline, flight_time, return_flight_time, flight_price) 
                  VALUES ($uid, '$title', '{$_POST['country']}', '{$_POST['currency']}', '$type', '{$_POST['airline']}', $f_time, $r_time, {$_POST['flight_price']})");
    header("Location: ?trip=".$conn->insert_id); exit;
}

if (isset($_POST['save_expense'])) {
    $tid = $_POST['trip_id'];
    $amt_k = intval($_POST['amount_krw']);
    $part = max(1, intval($_POST['participants']));
    $share = isset($_POST['is_my_payment']) ? $amt_k : (int)round($amt_k / $part);
    $conn->query("INSERT INTO expenses (trip_id, user_id, category, description, amount_foreign, amount_krw, my_share_krw, paid_by, participants, currency, expense_date) 
                  VALUES ($tid, {$_SESSION['user_id']}, '{$_POST['category']}', '{$_POST['description']}', {$_POST['amount_foreign']}, $amt_k, $share, '{$_POST['paid_by']}', $part, '{$_POST['currency']}', '{$_POST['expense_date']}')");
    header("Location: ?trip=$tid"); exit;
}

// 데이터 로드
$current_trip = null; $expenses = []; $trip_total_krw = 0;
if (isset($_GET['trip']) && isset($_SESSION['user_id'])) {
    $tid = intval($_GET['trip']);
    $res = $conn->query("SELECT * FROM trips WHERE id=$tid AND user_id={$_SESSION['user_id']}");
    $current_trip = $res->fetch_assoc();
    if ($current_trip) {
        $eres = $conn->query("SELECT * FROM expenses WHERE trip_id=$tid ORDER BY expense_date DESC");
        while ($row = $eres->fetch_assoc()) { $expenses[] = $row; $trip_total_krw += $row['my_share_krw']; }
    }
}
$trips = (isset($_SESSION['user_id'])) ? $conn->query("SELECT t.*, (SELECT SUM(my_share_krw) FROM expenses WHERE trip_id=t.id) as total_expense FROM trips t WHERE user_id={$_SESSION['user_id']} ORDER BY created_at DESC") : [];

$category_icons = ['식비'=>'fa-utensils', '숙박'=>'fa-bed', '교통'=>'fa-bus', '쇼핑'=>'fa-bag-shopping', '관광'=>'fa-camera', '기타'=>'fa-circle-dot'];
$category_colors = ['식비'=>'bg-orange-100 text-orange-600', '숙박'=>'bg-blue-100 text-blue-600', '교통'=>'bg-green-100 text-green-600', '쇼핑'=>'bg-pink-100 text-pink-600', '관광'=>'bg-purple-100 text-purple-600', '기타'=>'bg-slate-100 text-slate-600'];
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI 트래블 가계부</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>.modal-bg { background: rgba(0,0,0,0.4); backdrop-filter: blur(4px); }</style>
</head>
<body class="bg-slate-50 text-slate-900 min-h-screen">

<?php if (!isset($_SESSION['user'])): ?>
<div class="flex items-center justify-center min-h-screen px-4">
    <div class="w-full max-w-md">
        <?php if ($error): ?><div class="bg-red-50 text-red-600 p-4 rounded-2xl mb-4 font-bold"><?= $error ?></div><?php endif; ?>
        <?php if ($success): ?><div class="bg-green-50 text-green-600 p-4 rounded-2xl mb-4 font-bold"><?= $success ?></div><?php endif; ?>
        <div id="login-form" class="bg-white p-10 rounded-[2.5rem] shadow-2xl">
            <h2 class="text-3xl font-black text-center mb-8 text-indigo-600">Travel Ledger</h2>
            <form method="POST">
                <input type="text" name="login_id" placeholder="아이디 또는 이메일" class="w-full p-4 border rounded-2xl mb-4 bg-slate-50" required>
                <input type="password" name="password" placeholder="비밀번호" class="w-full p-4 border rounded-2xl mb-6 bg-slate-50" required>
                <button name="login" class="w-full py-4 bg-indigo-600 text-white rounded-2xl font-bold text-lg shadow-lg">로그인</button>
            </form>
            <p class="text-center mt-6 text-slate-400">계정이 없으신가요? <button onclick="toggleReg(true)" class="text-indigo-600 font-bold">회원가입</button></p>
        </div>
        <div id="register-form" class="hidden bg-white p-10 rounded-[2.5rem] shadow-2xl">
            <h2 class="text-2xl font-black text-center mb-6">회원가입</h2>
            <form method="POST" class="space-y-4">
                <input type="text" name="reg_name" placeholder="이름" class="w-full p-4 border rounded-2xl bg-slate-50" required>
                <input type="text" name="reg_username" placeholder="아이디 (4~20자)" class="w-full p-4 border rounded-2xl bg-slate-50" required>
                <input type="email" name="reg_email" placeholder="이메일" class="w-full p-4 border rounded-2xl bg-slate-50" required>
                <input type="tel" name="reg_phone" placeholder="전화번호" class="w-full p-4 border rounded-2xl bg-slate-50" required>
                <input type="password" name="reg_password" placeholder="비밀번호 (영문/숫자/특수)" class="w-full p-4 border rounded-2xl bg-slate-50" required>
                <input type="password" name="reg_password_confirm" placeholder="비밀번호 확인" class="w-full p-4 border rounded-2xl bg-slate-50" required>
                <button name="register" class="w-full py-4 bg-slate-800 text-white rounded-2xl font-bold">가입하기</button>
            </form>
            <button onclick="toggleReg(false)" class="w-full text-indigo-600 font-bold mt-4">← 로그인으로</button>
        </div>
    </div>
</div>

<?php else: ?>
<nav class="bg-white/80 backdrop-blur-md sticky top-0 z-50 border-b p-4 flex justify-between items-center px-6">
    <a href="?" class="font-black text-xl text-indigo-600">TRAVELER</a>
    <div class="flex items-center gap-4">
        <button onclick="document.getElementById('profile-modal').classList.remove('hidden')" class="flex items-center gap-2">
            <div class="w-8 h-8 rounded-full bg-indigo-100 text-indigo-600 flex items-center justify-center"><i class="fa-solid fa-user text-xs"></i></div>
            <span class="text-sm font-bold"><?= e($_SESSION['user_name']) ?>님</span>
        </button>
        <a href="?logout=true" class="text-xs font-bold text-red-400">LOGOUT</a>
    </div>
</nav>

<div class="max-w-2xl mx-auto py-8 px-4">
    <?php if ($current_trip): ?>
    <div class="bg-indigo-600 p-8 rounded-[2.5rem] text-white mb-6 shadow-xl relative overflow-hidden">
        <div class="relative z-10">
            <span class="text-xs font-bold bg-white/20 px-3 py-1 rounded-full uppercase"><?= e($current_trip['country']) ?> · <?= e($current_trip['currency']) ?></span>
            <h2 class="text-2xl font-black mt-3"><?= e($current_trip['title']) ?></h2>
            <p class="text-indigo-200 text-sm mt-1"><i class="fa-solid fa-plane-departure mr-1"></i><?= e($current_trip['airline']) ?> · <?= ($current_trip['trip_type']=='roundtrip')?'왕복':'편도' ?></p>
            <div class="grid grid-cols-2 gap-4 mt-6 pt-6 border-t border-white/20">
                <div><p class="text-indigo-200 text-xs font-bold">항공권</p><p class="text-xl font-black"><?= number_format($current_trip['flight_price']) ?>원</p></div>
                <div><p class="text-indigo-200 text-xs font-bold">지출(내 부담)</p><p class="text-xl font-black"><?= number_format($trip_total_krw) ?>원</p></div>
            </div>
        </div>
    </div>

    <button onclick="document.getElementById('expense-modal').classList.remove('hidden')" class="w-full py-4 bg-white border-2 border-dashed border-indigo-200 text-indigo-500 rounded-2xl font-bold mb-6 hover:bg-indigo-50 transition">+ 지출 내역 추가</button>

    <div class="space-y-3">
        <?php foreach ($expenses as $e): ?>
        <div class="bg-white rounded-2xl p-5 flex items-center gap-4 border border-slate-100 shadow-sm">
            <div class="w-12 h-12 <?= $category_colors[$e['category']] ?> rounded-xl flex items-center justify-center flex-shrink-0"><i class="fa-solid <?= $category_icons[$e['category']] ?>"></i></div>
            <div class="flex-1 min-w-0">
                <p class="font-bold text-slate-800 truncate"><?= e($e['description']) ?></p>
                <p class="text-xs text-slate-400"><?= $e['expense_date'] ?> · <?= $e['category'] ?></p>
            </div>
            <div class="text-right">
                <p class="font-black text-slate-800">내 부담 <?= number_format($e['my_share_krw']) ?>원</p>
                <p class="text-[10px] text-slate-400">총 <?= number_format($e['amount_krw']) ?>원 (<?= $e['participants'] ?>명)</p>
            </div>
        </div>
        <?php endforeach; ?>
    </div>

    <?php else: ?>
    <div id="step-1" class="bg-white p-8 rounded-[2.5rem] shadow-sm mb-8 border border-slate-100">
        <h2 class="text-2xl font-black mb-6">어디로 떠나시나요? ✈️</h2>
        <div class="space-y-5">
            <div>
                <label class="block text-sm font-bold text-slate-400 mb-2">목적지</label>
                <select id="target_country" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none" onchange="updateCurrency()">
                    <option value="VN" data-curr="VND">베트남 (VND)</option>
                    <option value="JP" data-curr="JPY">일본 (JPY)</option>
                    <option value="US" data-curr="USD">미국 (USD)</option>
                    <option value="EU" data-curr="EUR">유럽 (EUR)</option>
                </select>
            </div>
            <input type="text" id="trip_title" placeholder="여행 제목 (예: 다낭 3박 4일)" class="w-full p-4 border rounded-2xl bg-slate-50">
            <div class="p-5 bg-indigo-600 rounded-2xl text-white">
                <h4 class="text-xl font-black" id="rate_info">환율 로딩 중...</h4>
                <p class="text-xs text-indigo-300 mt-2" id="rate_source"></p>
            </div>
            <button onclick="nextStep(2)" class="w-full py-4 bg-indigo-600 text-white rounded-2xl font-bold text-lg shadow-lg shadow-indigo-100">다음 단계</button>
        </div>
    </div>

    <div id="step-2" class="hidden bg-white p-8 rounded-[2.5rem] shadow-sm mb-8 border border-slate-100">
        <h2 class="text-2xl font-black mb-6">항공권 정보 🎫</h2>
        <form method="POST" class="space-y-4">
            <input type="hidden" name="save_trip" value="1">
            <input type="hidden" name="country" id="form_country">
            <input type="hidden" name="currency" id="form_currency">
            <input type="hidden" name="trip_title" id="form_title">
            
            <div class="grid grid-cols-2 gap-2 mb-2">
                <button type="button" onclick="setTripType('roundtrip')" id="btn-round" class="p-4 border-2 rounded-2xl font-bold border-indigo-600 bg-indigo-50 text-indigo-600">왕복</button>
                <button type="button" onclick="setTripType('oneway')" id="btn-one" class="p-4 border-2 rounded-2xl font-bold border-slate-100 text-slate-400">편도</button>
                <input type="hidden" name="trip_type" id="form_trip_type" value="roundtrip">
            </div>
            
            <input type="text" name="airline" placeholder="항공사 (예: 대한항공)" class="w-full p-4 border rounded-2xl bg-slate-50">
            <div class="grid grid-cols-2 gap-3">
                <input type="datetime-local" name="flight_time" class="p-4 border rounded-2xl bg-slate-50">
                <input type="number" name="flight_price" placeholder="항공권 총액(원)" class="p-4 border rounded-2xl bg-slate-50">
            </div>
            <div id="return-box">
                <label class="block text-xs font-bold text-slate-400 mb-2">오는편 시간</label>
                <input type="datetime-local" name="return_flight_time" class="w-full p-4 border rounded-2xl bg-slate-50">
            </div>
            <button class="w-full py-4 bg-black text-white rounded-2xl font-bold text-lg">여행 생성하기</button>
            <button type="button" onclick="goBack()" class="w-full text-slate-400 font-bold mt-2">이전으로</button>
        </form>
    </div>

    <?php if ($trips): ?>
    <div class="space-y-4">
        <h3 class="font-black text-slate-400 uppercase tracking-widest text-xs">My Trips</h3>
        <?php foreach ($trips as $t): ?>
        <a href="?trip=<?= $t['id'] ?>" class="block bg-white p-6 rounded-[2rem] border border-slate-100 shadow-sm hover:shadow-md transition">
            <div class="flex justify-between items-center">
                <div>
                    <span class="text-[10px] font-bold bg-indigo-50 text-indigo-500 px-2 py-1 rounded-full"><?= e($t['country']) ?></span>
                    <h4 class="font-black text-slate-800 mt-2"><?= e($t['title']) ?></h4>
                </div>
                <div class="text-right">
                    <p class="text-lg font-black text-indigo-600"><?= number_format($t['flight_price'] + $t['total_expense']) ?>원</p>
                </div>
            </div>
        </a>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>
    <?php endif; ?>
</div>

<div id="expense-modal" class="hidden fixed inset-0 modal-bg z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-[2.5rem] p-8 w-full max-w-md shadow-2xl">
        <h3 class="text-xl font-black mb-6 text-center">지출 추가</h3>
        <form method="POST" class="space-y-4">
            <input type="hidden" name="save_expense" value="1">
            <input type="hidden" name="trip_id" value="<?= $current_trip['id'] ?? '' ?>">
            <input type="hidden" name="currency" value="<?= $current_trip['currency'] ?? '' ?>">
            
            <select name="category" class="w-full p-4 border rounded-2xl bg-slate-50 font-bold text-slate-600">
                <?php foreach($category_icons as $name => $icon): ?><option value="<?= $name ?>"><?= $name ?></option><?php endforeach; ?>
            </select>
            <input type="text" name="description" placeholder="지출 내용" class="w-full p-4 border rounded-2xl bg-slate-50" required>
            
            <div class="grid grid-cols-2 gap-3">
                <input type="number" step="0.01" name="amount_foreign" id="amt_f" placeholder="현지 금액" class="p-4 border rounded-2xl bg-slate-50" oninput="calcKrw()">
                <input type="number" name="amount_krw" id="amt_k" placeholder="원화 금액" class="p-4 border rounded-2xl bg-slate-50" oninput="calcForeign()">
            </div>

            <div class="grid grid-cols-2 gap-3">
                <input type="text" name="paid_by" value="<?= e($_SESSION['user_name']) ?>" class="p-4 border rounded-2xl bg-slate-50">
                <input type="number" name="participants" value="1" min="1" class="p-4 border rounded-2xl bg-slate-50">
            </div>
            
            <label class="flex items-center gap-2 text-sm font-bold text-slate-500 px-2">
                <input type="checkbox" name="is_my_payment" class="w-4 h-4"> 내가 전액 결제 (N빵 안함)
            </label>

            <input type="date" name="expense_date" value="<?= date('Y-m-d') ?>" class="w-full p-4 border rounded-2xl bg-slate-50">
            <button class="w-full py-4 bg-indigo-600 text-white rounded-2xl font-bold text-lg shadow-lg">저장하기</button>
            <button type="button" onclick="document.getElementById('expense-modal').classList.add('hidden')" class="w-full text-slate-400 font-bold">취소</button>
        </form>
    </div>
</div>

<div id="profile-modal" class="hidden fixed inset-0 modal-bg z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-[2.5rem] p-8 w-full max-w-md shadow-2xl">
        <h3 class="text-xl font-black mb-6">내 프로필</h3>
        <form method="POST" class="space-y-4">
            <input type="hidden" name="update_profile" value="1">
            <input type="text" name="profile_name" value="<?= e($_SESSION['user_name']) ?>" class="w-full p-4 border rounded-2xl bg-slate-50" required>
            <input type="email" name="profile_email" value="<?= e($_SESSION['user_email']) ?>" class="w-full p-4 border rounded-2xl bg-slate-50" required>
            <div class="pt-4 border-t border-slate-100">
                <p class="text-xs font-bold text-slate-400 mb-2">비밀번호 변경 시에만 입력</p>
                <input type="password" name="current_password" placeholder="현재 비밀번호" class="w-full p-4 border rounded-2xl bg-slate-50 mb-2">
                <input type="password" name="new_password" placeholder="새 비밀번호" class="w-full p-4 border rounded-2xl bg-slate-50">
            </div>
            <button class="w-full py-4 bg-indigo-600 text-white rounded-2xl font-bold">수정 완료</button>
            <button type="button" onclick="document.getElementById('profile-modal').classList.add('hidden')" class="w-full text-slate-400 font-bold">닫기</button>
        </form>
    </div>
</div>
<?php endif; ?>

<script>
let liveRates = {}; let selectedCurrency = 'VND';
async function loadRates() {
    try {
        const res = await fetch('https://api.exchangerate-api.com/v4/latest/KRW');
        const data = await res.json(); liveRates = data.rates;
        document.getElementById('rate_source').innerText = '실시간 환율 업데이트 완료'; updateCurrency();
    } catch(e) { liveRates = {VND: 18, JPY: 0.11, USD: 0.00074, EUR: 0.00068}; updateCurrency(); }
}

function updateCurrency() {
    const sel = document.getElementById('target_country'); if(!sel) return;
    selectedCurrency = sel.options[sel.selectedIndex].getAttribute('data-curr');
    const krwPerOne = (1 / liveRates[selectedCurrency]).toFixed(2);
    document.getElementById('rate_info').innerText = `1 ${selectedCurrency} = ${Number(krwPerOne).toLocaleString()} 원`;
}

function calcKrw() {
    const f = parseFloat(document.getElementById('amt_f').value) || 0;
    const curr = '<?= $current_trip['currency'] ?? '' ?>' || selectedCurrency;
    if(liveRates[curr]) document.getElementById('amt_k').value = Math.round(f / liveRates[curr]);
}

function calcForeign() {
    const k = parseFloat(document.getElementById('amt_k').value) || 0;
    const curr = '<?= $current_trip['currency'] ?? '' ?>' || selectedCurrency;
    if(liveRates[curr]) document.getElementById('amt_f').value = (k * liveRates[curr]).toFixed(2);
}

function setTripType(type) {
    document.getElementById('form_trip_type').value = type;
    document.getElementById('return-box').style.display = (type === 'roundtrip') ? 'block' : 'none';
    document.getElementById('btn-round').className = (type === 'roundtrip') ? 'p-4 border-2 rounded-2xl font-bold border-indigo-600 bg-indigo-50 text-indigo-600' : 'p-4 border-2 rounded-2xl font-bold border-slate-100 text-slate-400';
    document.getElementById('btn-one').className = (type === 'oneway') ? 'p-4 border-2 rounded-2xl font-bold border-indigo-600 bg-indigo-50 text-indigo-600' : 'p-4 border-2 rounded-2xl font-bold border-slate-100 text-slate-400';
}

function nextStep(s) {
    document.getElementById('form_country').value = document.getElementById('target_country').value;
    document.getElementById('form_currency').value = selectedCurrency;
    document.getElementById('form_title').value = document.getElementById('trip_title').value || '나의 여정';
    document.getElementById('step-1').classList.add('hidden');
    document.getElementById('step-2').classList.remove('hidden');
}

function goBack() { document.getElementById('step-2').classList.add('hidden'); document.getElementById('step-1').classList.remove('hidden'); }
function toggleReg(show) {
    document.getElementById('login-form').classList.toggle('hidden', show);
    document.getElementById('register-form').classList.toggle('hidden', !show);
}
window.onload = loadRates;
</script>
</body>
</html>