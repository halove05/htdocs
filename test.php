<?php
$host = "mariadb";          // 스크린샷 '내부 연결'에 적힌 이름
$user = "root";             // 별도로 설정하지 않으셨다면 기본값은 root입니다
$pw = "4396";      // DB 생성 시 입력했던 비밀번호
$dbName = "mariadb";    // DB 생성 시 입력했던 데이터베이스 이름
$port = 3306;               // 마리아DB 기본 포트
session_start();
ini_set('display_errors', 1);
error_reporting(E_ALL);
$conn = new mysqli($host, $user, $pw, $dbName, $port);
$conn->set_charset("utf8mb4");

// 테이블 생성
$conn->query("CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY, 
    username VARCHAR(50) UNIQUE,
    name VARCHAR(100),
    email VARCHAR(150) UNIQUE,
    phone VARCHAR(30),
    password VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)");
$conn->query("ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(100)");
$conn->query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(150) UNIQUE");
$conn->query("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(30)");
$conn->query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at DATETIME NULL");
$conn->query("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified_at DATETIME NULL");
$conn->query("CREATE TABLE IF NOT EXISTS verification_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    purpose VARCHAR(50),
    channel VARCHAR(20),
    target VARCHAR(150),
    code_hash VARCHAR(255),
    expires_at DATETIME,
    consumed_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_verification_lookup (purpose, target(100), consumed_at, expires_at)
)");
$conn->query("CREATE TABLE IF NOT EXISTS trips (
    id INT AUTO_INCREMENT PRIMARY KEY, 
    user_id INT, 
    title VARCHAR(255), 
    country VARCHAR(10), 
    currency VARCHAR(10),
    trip_type VARCHAR(10) DEFAULT 'roundtrip',
    airline VARCHAR(100), 
    flight_time DATETIME, 
    return_flight_time DATETIME,
    flight_price INT DEFAULT 0,
    return_flight_price INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)");
$conn->query("ALTER TABLE trips ADD COLUMN IF NOT EXISTS return_flight_time DATETIME");
$conn->query("ALTER TABLE trips ADD COLUMN IF NOT EXISTS return_flight_price INT DEFAULT 0");
$conn->query("ALTER TABLE trips ADD COLUMN IF NOT EXISTS trip_type VARCHAR(10) DEFAULT 'roundtrip'");
$conn->query("CREATE TABLE IF NOT EXISTS expenses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    trip_id INT,
    user_id INT,
    category VARCHAR(50),
    description VARCHAR(255),
    amount_foreign DECIMAL(15,2),
    amount_krw INT,
    my_share_krw INT DEFAULT 0,
    paid_by VARCHAR(100),
    participants INT DEFAULT 1,
    currency VARCHAR(10),
    expense_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)");
$conn->query("ALTER TABLE expenses ADD COLUMN IF NOT EXISTS my_share_krw INT DEFAULT 0");
$conn->query("ALTER TABLE expenses ADD COLUMN IF NOT EXISTS paid_by VARCHAR(100)");
$conn->query("ALTER TABLE expenses ADD COLUMN IF NOT EXISTS participants INT DEFAULT 1");

$error = '';
$success = '';
$auth_panel = 'login';
$recovery_result = null;
$form_values = [
    'reg_name' => '',
    'reg_username' => '',
    'reg_email' => '',
    'reg_phone' => '',
    'find_email' => '',
];

// ── 헬퍼 함수 ──────────────────────────────────────────────
function e(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

// [FIX] csrf_token() 함수 정의 추가
function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// [FIX] CSRF 토큰 검증 함수
function verify_csrf(): bool {
    return isset($_POST['csrf_token']) && $_POST['csrf_token'] === ($_SESSION['csrf_token'] ?? '');
}

function utf8_length(string $value): int {
    if (function_exists('mb_strlen')) {
        return mb_strlen($value, 'UTF-8');
    }

    if (preg_match_all('/./us', $value, $matches) !== false) {
        return count($matches[0]);
    }

    return strlen($value);
}

function isValidPassword(string $password): bool {
    return (bool) preg_match('/^(?=.*[A-Za-z])(?=.*\\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:\\|,.<>\/?]).{8,20}$/', $password);
}

function isValidPhone(string $phone): bool {
    return (bool) preg_match('/^01[016789]-?\\d{3,4}-?\\d{4}$/', $phone);
}

function normalizePhone(string $phone): string {
    return preg_replace('/\D+/', '', $phone);
}

function isValidUsername(string $username): bool {
    return (bool) preg_match('/^[A-Za-z0-9_]{4,20}$/', $username);
}

function generateVerificationCode(): string {
    return (string) random_int(100000, 999999);
}

function saveVerificationCode(mysqli $conn, string $purpose, string $channel, string $target, string $code): void {
    $stmt = $conn->prepare("INSERT INTO verification_codes (purpose, channel, target, code_hash, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))");
    $hash = password_hash($code, PASSWORD_DEFAULT);
    $stmt->bind_param('ssss', $purpose, $channel, $target, $hash);
    $stmt->execute();
    $stmt->close();
}

function verifyCode(mysqli $conn, string $purpose, string $target, string $code, bool $consume = false): bool {
    $stmt = $conn->prepare("SELECT id, code_hash FROM verification_codes WHERE purpose=? AND target=? AND consumed_at IS NULL AND expires_at >= NOW() ORDER BY id DESC LIMIT 1");
    $stmt->bind_param('ss', $purpose, $target);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$row || !password_verify($code, $row['code_hash'])) {
        return false;
    }

    if ($consume) {
        $up = $conn->prepare("UPDATE verification_codes SET consumed_at=NOW() WHERE id=?");
        $id = (int) $row['id'];
        $up->bind_param('i', $id);
        $up->execute();
        $up->close();
    }

    return true;
}

function sendVerificationEmail(string $email, string $code): bool {
    $subject = 'Travel Ledger 인증번호';
    $message = "Travel Ledger 인증번호는 {$code} 입니다.\n10분 안에 입력해주세요.";
    $headers = "From: no-reply@travel-ledger.local\r\nContent-Type: text/plain; charset=UTF-8";

    return @mail($email, $subject, $message, $headers);
}

function maskPhone(string $phone): string {
    $digits = normalizePhone($phone);
    if (strlen($digits) < 8) {
        return $phone;
    }

    return substr($digits, 0, 3) . '-****-' . substr($digits, -4);
}

// ── 인증번호 발송 / 계정 찾기 ─────────────────────────────
if (isset($_POST['send_reg_email_code'])) {
    $auth_panel = 'register';
    $form_values['reg_name'] = trim($_POST['reg_name'] ?? '');
    $form_values['reg_username'] = trim($_POST['reg_username'] ?? '');
    $form_values['reg_email'] = trim($_POST['reg_email'] ?? '');
    $form_values['reg_phone'] = trim($_POST['reg_phone'] ?? '');

    if (!filter_var($form_values['reg_email'], FILTER_VALIDATE_EMAIL)) {
        $error = '인증번호를 받을 이메일을 올바르게 입력해주세요.';
    } else {
        $stmt = $conn->prepare("SELECT id FROM users WHERE email=? LIMIT 1");
        $stmt->bind_param('s', $form_values['reg_email']);
        $stmt->execute();
        $exists = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if ($exists) {
            $error = '이미 사용 중인 이메일입니다.';
        } else {
            $code = generateVerificationCode();
            saveVerificationCode($conn, 'register_email', 'email', $form_values['reg_email'], $code);
            $sent = sendVerificationEmail($form_values['reg_email'], $code);
            $success = $sent
                ? '이메일 인증번호를 보냈습니다. 10분 안에 입력해주세요.'
                : '메일 발송 설정이 없어 개발 확인용 인증번호를 표시합니다: ' . $code;
        }
    }
}

if (isset($_POST['send_reg_phone_code'])) {
    $auth_panel = 'register';
    $form_values['reg_name'] = trim($_POST['reg_name'] ?? '');
    $form_values['reg_username'] = trim($_POST['reg_username'] ?? '');
    $form_values['reg_email'] = trim($_POST['reg_email'] ?? '');
    $form_values['reg_phone'] = trim($_POST['reg_phone'] ?? '');
    $phone_target = normalizePhone($form_values['reg_phone']);

    if (!isValidPhone($form_values['reg_phone'])) {
        $error = '인증번호를 받을 전화번호를 올바르게 입력해주세요.';
    } else {
        $code = generateVerificationCode();
        saveVerificationCode($conn, 'register_phone', 'phone', $phone_target, $code);
        $success = '휴대폰 인증번호를 발급했습니다. 개발 환경 인증번호: ' . $code;
    }
}

if (isset($_POST['send_recovery_email_code'])) {
    $auth_panel = 'recovery';
    $form_values['find_email'] = trim($_POST['find_email'] ?? '');

    if (!filter_var($form_values['find_email'], FILTER_VALIDATE_EMAIL)) {
        $error = '가입한 이메일을 올바르게 입력해주세요.';
    } else {
        $stmt = $conn->prepare("SELECT id FROM users WHERE email=? LIMIT 1");
        $stmt->bind_param('s', $form_values['find_email']);
        $stmt->execute();
        $exists = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$exists) {
            $error = '해당 이메일로 가입된 계정을 찾을 수 없습니다.';
        } else {
            $code = generateVerificationCode();
            saveVerificationCode($conn, 'account_recovery', 'email', $form_values['find_email'], $code);
            $sent = sendVerificationEmail($form_values['find_email'], $code);
            $success = $sent
                ? '계정 찾기 인증번호를 이메일로 보냈습니다.'
                : '메일 발송 설정이 없어 개발 확인용 인증번호를 표시합니다: ' . $code;
        }
    }
}

if (isset($_POST['recover_account'])) {
    $auth_panel = 'recovery';
    $form_values['find_email'] = trim($_POST['find_email'] ?? '');
    $recovery_code = trim($_POST['recovery_email_code'] ?? '');
    $new_password_raw = $_POST['recovery_new_password'] ?? '';
    $new_password_confirm_raw = $_POST['recovery_new_password_confirm'] ?? '';

    if (!filter_var($form_values['find_email'], FILTER_VALIDATE_EMAIL)) {
        $error = '가입한 이메일을 올바르게 입력해주세요.';
    } elseif (!verifyCode($conn, 'account_recovery', $form_values['find_email'], $recovery_code, false)) {
        $error = '이메일 인증번호가 올바르지 않거나 만료되었습니다.';
    } else {
        $stmt = $conn->prepare("SELECT id, username, name, email, phone, created_at FROM users WHERE email=? LIMIT 1");
        $stmt->bind_param('s', $form_values['find_email']);
        $stmt->execute();
        $recovery_result = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$recovery_result) {
            $error = '계정 정보를 찾을 수 없습니다.';
        } elseif ($new_password_raw !== '' || $new_password_confirm_raw !== '') {
            if (!isValidPassword($new_password_raw)) {
                $error = '새 비밀번호는 8~20자이며 영문, 숫자, 특수문자를 모두 포함해야 합니다.';
            } elseif ($new_password_raw !== $new_password_confirm_raw) {
                $error = '새 비밀번호 확인이 일치하지 않습니다.';
            } else {
                $hashedPassword = password_hash($new_password_raw, PASSWORD_DEFAULT);
                $up = $conn->prepare("UPDATE users SET password=? WHERE id=?");
                $uid = (int) $recovery_result['id'];
                $up->bind_param('si', $hashedPassword, $uid);
                $up->execute();
                $up->close();
                verifyCode($conn, 'account_recovery', $form_values['find_email'], $recovery_code, true);
                $success = '회원정보를 확인했고 비밀번호를 새로 설정했습니다. 이제 로그인해주세요.';
            }
        } else {
            $success = '이메일 인증이 완료되었습니다. 아래 회원정보를 확인해주세요.';
        }
    }
}

// ── 회원가입 ───────────────────────────────────────────────
if (isset($_POST['register'])) {
    $auth_panel = 'register';
    $name_raw     = trim($_POST['reg_name'] ?? '');
    $username_raw = trim($_POST['reg_username'] ?? '');
    $email_raw    = trim($_POST['reg_email'] ?? '');
    $phone_raw    = trim($_POST['reg_phone'] ?? '');
    $password_raw = $_POST['reg_password'] ?? '';
    $password_confirm_raw = $_POST['reg_password_confirm'] ?? '';
    $email_code_raw = trim($_POST['reg_email_code'] ?? '');
    $phone_code_raw = trim($_POST['reg_phone_code'] ?? '');
    $phone_target = normalizePhone($phone_raw);

    $form_values['reg_name'] = $name_raw;
    $form_values['reg_username'] = $username_raw;
    $form_values['reg_email'] = $email_raw;
    $form_values['reg_phone'] = $phone_raw;

    if ($name_raw === '' || utf8_length($name_raw) < 2) {
        $error = '이름은 2자 이상 입력해주세요.';
    } elseif (!isValidUsername($username_raw)) {
        $error = '아이디는 4~20자의 영문, 숫자, 밑줄(_)만 사용할 수 있습니다.';
    } elseif (!filter_var($email_raw, FILTER_VALIDATE_EMAIL)) {
        $error = '올바른 이메일 형식을 입력해주세요.';
    } elseif (!isValidPhone($phone_raw)) {
        $error = '전화번호 형식이 올바르지 않습니다. 예: 01012345678 또는 010-1234-5678';
    } elseif (!isValidPassword($password_raw)) {
        $error = '비밀번호는 8~20자이며 영문, 숫자, 특수문자를 모두 포함해야 합니다.';
    } elseif ($password_raw !== $password_confirm_raw) {
        $error = '비밀번호 확인이 일치하지 않습니다.';
    } elseif (!verifyCode($conn, 'register_email', $email_raw, $email_code_raw, false)) {
        $error = '이메일 인증번호가 올바르지 않거나 만료되었습니다.';
    } elseif (!verifyCode($conn, 'register_phone', $phone_target, $phone_code_raw, false)) {
        $error = '휴대폰 인증번호가 올바르지 않거나 만료되었습니다.';
    } else {
        $password = password_hash($password_raw, PASSWORD_DEFAULT);
        // [FIX] Prepared Statement 사용
        $stmt = $conn->prepare("INSERT INTO users (username, name, email, phone, password, email_verified_at, phone_verified_at) VALUES (?, ?, ?, ?, ?, NOW(), NOW())");
        $stmt->bind_param('sssss', $username_raw, $name_raw, $email_raw, $phone_raw, $password);
        try {
            if ($stmt->execute()) {
                verifyCode($conn, 'register_email', $email_raw, $email_code_raw, true);
                verifyCode($conn, 'register_phone', $phone_target, $phone_code_raw, true);
                $auth_panel = 'login';
                $success = '이메일과 휴대폰 인증이 완료되었습니다. 로그인해주세요.';
            } else {
                $error = 'DB 오류가 발생했습니다.';
            }
        } catch (mysqli_sql_exception $ex) {
            if ($conn->errno === 1062) {
                // 중복 확인
                $dupStmt = $conn->prepare("SELECT username, email FROM users WHERE username=? OR email=? LIMIT 1");
                $dupStmt->bind_param('ss', $username_raw, $email_raw);
                $dupStmt->execute();
                $dup = $dupStmt->get_result()->fetch_assoc();
                $dupStmt->close();
                if ($dup && $dup['username'] === $username_raw) {
                    $error = '이미 사용 중인 아이디입니다.';
                } elseif ($dup && $dup['email'] === $email_raw) {
                    $error = '이미 사용 중인 이메일입니다.';
                } else {
                    $error = '이미 가입된 정보가 있습니다.';
                }
            } else {
                $error = 'DB 오류: ' . $ex->getMessage();
            }
        }
        $stmt->close();
    }
}

// ── 로그인 ─────────────────────────────────────────────────
if (isset($_POST['login'])) {
    $login_id_raw  = trim($_POST['login_id'] ?? '');
    $login_password = $_POST['password'] ?? '';
    // [FIX] Prepared Statement 사용
    $stmt = $conn->prepare("SELECT * FROM users WHERE username=? OR email=? LIMIT 1");
    $stmt->bind_param('ss', $login_id_raw, $login_id_raw);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    if ($user && password_verify($login_password, $user['password'])) {
        session_regenerate_id(true);
        $_SESSION['user']       = $user['username'];
        $_SESSION['user_name']  = $user['name'] ?: $user['username'];
        $_SESSION['user_email'] = $user['email'] ?? '';
        $_SESSION['user_id']    = $user['id'];
    } else {
        $error = '아이디/이메일 또는 비밀번호가 틀렸습니다.';
    }
}

// ── 로그아웃 ───────────────────────────────────────────────
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: ?");
    exit;
}

// ── 프로필 수정 ────────────────────────────────────────────
if (isset($_POST['update_profile'])) {
    // [FIX] CSRF 검증
    if (!verify_csrf()) {
        $error = '보안 토큰이 유효하지 않습니다. 다시 시도해주세요.';
    } else {
        $uid  = (int) ($_SESSION['user_id'] ?? 0);
        $name_raw     = trim($_POST['profile_name'] ?? '');
        $username_raw = trim($_POST['profile_username'] ?? '');
        $email_raw    = trim($_POST['profile_email'] ?? '');
        $phone_raw    = trim($_POST['profile_phone'] ?? '');
        $current_password_raw     = $_POST['current_password'] ?? '';
        $new_password_raw         = $_POST['new_password'] ?? '';
        $new_password_confirm_raw = $_POST['new_password_confirm'] ?? '';

        $stmt = $conn->prepare("SELECT * FROM users WHERE id = ? LIMIT 1");
        $stmt->bind_param('i', $uid);
        $stmt->execute();
        $currentUser = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$currentUser) {
            $error = '사용자 정보를 찾을 수 없습니다.';
        } elseif ($name_raw === '' || utf8_length($name_raw) < 2) {
            $error = '이름은 2자 이상 입력해주세요.';
        } elseif (!isValidUsername($username_raw)) {
            $error = '아이디는 4~20자의 영문, 숫자, 밑줄(_)만 사용할 수 있습니다.';
        } elseif (!filter_var($email_raw, FILTER_VALIDATE_EMAIL)) {
            $error = '올바른 이메일 형식을 입력해주세요.';
        } elseif (!isValidPhone($phone_raw)) {
            $error = '전화번호 형식이 올바르지 않습니다.';
        } elseif ($new_password_raw !== '' && !password_verify($current_password_raw, $currentUser['password'])) {
            $error = '비밀번호를 변경하려면 현재 비밀번호를 정확히 입력해주세요.';
        } elseif ($new_password_raw !== '' && !isValidPassword($new_password_raw)) {
            $error = '새 비밀번호는 8~20자이며 영문, 숫자, 특수문자를 모두 포함해야 합니다.';
        } elseif ($new_password_raw !== '' && $new_password_raw !== $new_password_confirm_raw) {
            $error = '새 비밀번호 확인이 일치하지 않습니다.';
        } else {
            try {
                $dupStmt = $conn->prepare("SELECT id, username, email FROM users WHERE (email=? OR username=?) AND id<>? LIMIT 1");
                $dupStmt->bind_param('ssi', $email_raw, $username_raw, $uid);
                $dupStmt->execute();
                $dupUser = $dupStmt->get_result()->fetch_assoc();
                $dupStmt->close();

                if ($dupUser && $dupUser['email'] === $email_raw) {
                    $error = '이미 사용 중인 이메일입니다.';
                } elseif ($dupUser && $dupUser['username'] === $username_raw) {
                    $error = '이미 사용 중인 아이디입니다.';
                } else {
                    if ($new_password_raw !== '') {
                        $hashedPassword = password_hash($new_password_raw, PASSWORD_DEFAULT);
                        $upStmt = $conn->prepare("UPDATE users SET username=?, name=?, email=?, phone=?, password=? WHERE id=?");
                        $upStmt->bind_param('sssssi', $username_raw, $name_raw, $email_raw, $phone_raw, $hashedPassword, $uid);
                    } else {
                        $upStmt = $conn->prepare("UPDATE users SET username=?, name=?, email=?, phone=? WHERE id=?");
                        $upStmt->bind_param('ssssi', $username_raw, $name_raw, $email_raw, $phone_raw, $uid);
                    }
                    $upStmt->execute();
                    $upStmt->close();

                    $_SESSION['user_name']  = $name_raw;
                    $_SESSION['user']       = $username_raw;
                    $_SESSION['user_email'] = $email_raw;
                    $success = '회원 정보가 수정되었습니다.';
                }
            } catch (mysqli_sql_exception $ex) {
                $error = '회원 정보 수정 중 오류가 발생했습니다: ' . $ex->getMessage();
            }
        }
    }
}

// ── 여행 저장 ──────────────────────────────────────────────
if (isset($_POST['save_trip']) && isset($_SESSION['user_id'])) {
    $uid         = (int) $_SESSION['user_id'];
    $title       = $_POST['trip_title'] ?? '';
    $country     = $_POST['country'] ?? '';
    $currency    = $_POST['currency'] ?? '';
    $trip_type   = $_POST['trip_type'] ?? 'roundtrip';
    $airline     = $_POST['airline'] ?? '';
    $flight_time_raw        = $_POST['flight_time'] ?? '';
    $return_flight_time_raw = $_POST['return_flight_time'] ?? '';
    $flight_price = intval($_POST['flight_price'] ?? 0);

    $flight_time_val        = !empty($flight_time_raw) ? $flight_time_raw : null;
    $return_flight_time_val = ($trip_type === 'roundtrip' && !empty($return_flight_time_raw)) ? $return_flight_time_raw : null;
    $return_flight_price    = 0;

    // [FIX] Prepared Statement 사용
    $stmt = $conn->prepare("INSERT INTO trips (user_id, title, country, currency, trip_type, airline, flight_time, return_flight_time, flight_price, return_flight_price) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param('isssssssii', $uid, $title, $country, $currency, $trip_type, $airline, $flight_time_val, $return_flight_time_val, $flight_price, $return_flight_price);
    $stmt->execute();
    $new_trip_id = $conn->insert_id;
    $stmt->close();

    $_SESSION['current_trip'] = $new_trip_id;
    header("Location: ?trip=" . $new_trip_id);
    exit;
}

// ── 항공편 수정 ────────────────────────────────────────────
if (isset($_POST['update_flight']) && isset($_SESSION['user_id'])) {
    $tid      = intval($_POST['trip_id'] ?? 0);
    $uid      = (int) $_SESSION['user_id'];
    $trip_type   = $_POST['trip_type'] ?? 'roundtrip';
    $airline     = $_POST['airline'] ?? '';
    $flight_time_raw        = $_POST['flight_time'] ?? '';
    $return_flight_time_raw = $_POST['return_flight_time'] ?? '';
    $flight_price = intval($_POST['flight_price'] ?? 0);
    $return_flight_price = 0;

    $flight_time_val        = !empty($flight_time_raw) ? $flight_time_raw : null;
    $return_flight_time_val = ($trip_type === 'roundtrip' && !empty($return_flight_time_raw)) ? $return_flight_time_raw : null;

    // [FIX] Prepared Statement 사용
    $stmt = $conn->prepare("UPDATE trips SET trip_type=?, airline=?, flight_time=?, return_flight_time=?, flight_price=?, return_flight_price=? WHERE id=? AND user_id=?");
    $stmt->bind_param('ssssiiis', $trip_type, $airline, $flight_time_val, $return_flight_time_val, $flight_price, $return_flight_price, $tid, $uid);
    // bind_param 타입 수정: int 필드는 i
    $stmt->close();

    // 올바른 바인딩으로 재실행
    $stmt2 = $conn->prepare("UPDATE trips SET trip_type=?, airline=?, flight_time=?, return_flight_time=?, flight_price=?, return_flight_price=? WHERE id=? AND user_id=?");
    $stmt2->bind_param('ssssiiii', $trip_type, $airline, $flight_time_val, $return_flight_time_val, $flight_price, $return_flight_price, $tid, $uid);
    $stmt2->execute();
    $stmt2->close();

    header("Location: ?trip=$tid");
    exit;
}

// ── 지출 저장 ──────────────────────────────────────────────
if (isset($_POST['save_expense']) && isset($_SESSION['user_id'])) {
    $trip_id        = intval($_POST['trip_id'] ?? 0);
    $uid            = (int) $_SESSION['user_id'];
    $category       = $_POST['category'] ?? '기타';
    $description    = $_POST['description'] ?? '';
    $amount_foreign = floatval($_POST['amount_foreign'] ?? 0);
    $amount_krw     = intval($_POST['amount_krw'] ?? 0);
    $currency       = $_POST['currency'] ?? '';
    $expense_date   = $_POST['expense_date'] ?? date('Y-m-d');
    $paid_by        = $_POST['paid_by'] ?? ($_SESSION['user'] ?? '');
    $participants   = max(1, intval($_POST['participants'] ?? 1));
    $is_my_payment  = isset($_POST['is_my_payment']) ? 1 : 0;

    $my_share_krw = $is_my_payment ? $amount_krw : (int) round($amount_krw / $participants);

    // [FIX] Prepared Statement 사용
    $stmt = $conn->prepare("INSERT INTO expenses (trip_id, user_id, category, description, amount_foreign, amount_krw, my_share_krw, paid_by, participants, currency, expense_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param('iissdiiisis', $trip_id, $uid, $category, $description, $amount_foreign, $amount_krw, $my_share_krw, $paid_by, $participants, $currency, $expense_date);
    $stmt->execute();
    $stmt->close();

    header("Location: ?trip=$trip_id");
    exit;
}

// ── 지출 삭제 ──────────────────────────────────────────────
if (isset($_GET['del_expense']) && isset($_SESSION['user_id'])) {
    $eid = intval($_GET['del_expense']);
    $tid = intval($_GET['trip'] ?? 0);
    $uid = (int) $_SESSION['user_id'];
    // [FIX] Prepared Statement 사용
    $stmt = $conn->prepare("DELETE FROM expenses WHERE id=? AND user_id=?");
    $stmt->bind_param('ii', $eid, $uid);
    $stmt->execute();
    $stmt->close();
    header("Location: ?trip=$tid");
    exit;
}

// ── 여행 삭제 ──────────────────────────────────────────────
if (isset($_GET['del_trip']) && isset($_SESSION['user_id'])) {
    $tid = intval($_GET['del_trip']);
    $uid = (int) $_SESSION['user_id'];
    // [FIX] Prepared Statement 사용
    $stmt = $conn->prepare("DELETE FROM expenses WHERE trip_id=?");
    $stmt->bind_param('i', $tid);
    $stmt->execute();
    $stmt->close();

    $stmt2 = $conn->prepare("DELETE FROM trips WHERE id=? AND user_id=?");
    $stmt2->bind_param('ii', $tid, $uid);
    $stmt2->execute();
    $stmt2->close();
    header("Location: ?");
    exit;
}

// ── 현재 여행 조회 ─────────────────────────────────────────
$current_trip  = null;
$expenses      = [];
$trip_total_krw = 0;

if (isset($_GET['trip']) && isset($_SESSION['user_id'])) {
    $tid = intval($_GET['trip']);
    $uid = (int) $_SESSION['user_id'];
    // [FIX] Prepared Statement 사용
    $stmt = $conn->prepare("SELECT * FROM trips WHERE id=? AND user_id=?");
    $stmt->bind_param('ii', $tid, $uid);
    $stmt->execute();
    $current_trip = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if ($current_trip) {
        $stmt2 = $conn->prepare("SELECT * FROM expenses WHERE trip_id=? ORDER BY expense_date DESC, created_at DESC");
        $stmt2->bind_param('i', $tid);
        $stmt2->execute();
        $eres = $stmt2->get_result();
        $stmt2->close();
        while ($row = $eres->fetch_assoc()) {
            $expenses[]      = $row;
            $trip_total_krw += $row['my_share_krw'];
        }
    }
}

// ── 여행 목록 ──────────────────────────────────────────────
$trips = [];
if (isset($_SESSION['user_id'])) {
    $uid = (int) $_SESSION['user_id'];
    // [FIX] Prepared Statement 사용
    $stmt = $conn->prepare("SELECT t.*, (SELECT COALESCE(SUM(my_share_krw),0) FROM expenses WHERE trip_id=t.id) as total_expense FROM trips t WHERE user_id=? ORDER BY created_at DESC");
    $stmt->bind_param('i', $uid);
    $stmt->execute();
    $tres = $stmt->get_result();
    $stmt->close();
    while ($row = $tres->fetch_assoc()) $trips[] = $row;
}

// ── 현재 사용자 프로필 ─────────────────────────────────────
$current_user_profile = null;
if (isset($_SESSION['user_id'])) {
    $uid  = (int) $_SESSION['user_id'];
    $stmt = $conn->prepare("SELECT id, username, name, email, phone, created_at FROM users WHERE id=? LIMIT 1");
    $stmt->bind_param('i', $uid);
    $stmt->execute();
    $current_user_profile = $stmt->get_result()->fetch_assoc();
    $stmt->close();
}

$category_icons = [
    '식비' => 'fa-utensils', '숙박' => 'fa-bed', '교통' => 'fa-bus',
    '쇼핑' => 'fa-bag-shopping', '관광' => 'fa-camera', '기타' => 'fa-circle-dot'
];
$category_colors = [
    '식비' => 'bg-orange-100 text-orange-600', '숙박' => 'bg-blue-100 text-blue-600',
    '교통' => 'bg-green-100 text-green-600',   '쇼핑' => 'bg-pink-100 text-pink-600',
    '관광' => 'bg-purple-100 text-purple-600', '기타' => 'bg-slate-100 text-slate-600'
];
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI 트래블 가계부</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        .step-content { transition: all 0.3s ease; }
        .hidden { display: none; }
        .modal-bg { background: rgba(0,0,0,0.4); backdrop-filter: blur(4px); }
    </style>
</head>
<body class="bg-slate-50 text-slate-900 min-h-screen">

<?php if (!isset($_SESSION['user'])): ?>
<!-- ===== 로그인 / 회원가입 ===== -->
<div class="flex items-center justify-center min-h-screen px-4">
    <div class="w-full max-w-md">
        <?php if ($error): ?>
            <div class="bg-red-50 border border-red-200 text-red-600 p-4 rounded-2xl mb-4 text-sm font-bold"><?= e($error) ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="bg-green-50 border border-green-200 text-green-600 p-4 rounded-2xl mb-4 text-sm font-bold"><?= e($success) ?></div>
        <?php endif; ?>

        <div id="login-form" class="<?= $auth_panel === 'login' ? '' : 'hidden' ?> bg-white p-10 rounded-[2.5rem] shadow-2xl">
            <div class="text-center mb-8">
                <div class="inline-block p-4 bg-indigo-100 rounded-2xl text-indigo-600 mb-4">
                    <i class="fa-solid fa-wallet text-3xl"></i>
                </div>
                <h2 class="text-3xl font-black text-slate-800">Travel Ledger</h2>
                <p class="text-slate-400 mt-2">당신의 모든 여정을 기록하세요</p>
                <p class="text-xs text-slate-400 mt-3">아이디 또는 이메일로 로그인할 수 있어요.</p>
            </div>
            <form method="POST">
                <input type="text" name="login_id" placeholder="아이디 또는 이메일" class="w-full p-4 border rounded-2xl mb-4 outline-none focus:ring-2 focus:ring-indigo-500 bg-slate-50" required>
                <input type="password" name="password" placeholder="비밀번호" class="w-full p-4 border rounded-2xl mb-6 outline-none focus:ring-2 focus:ring-indigo-500 bg-slate-50" required>
                <button name="login" class="w-full py-4 bg-indigo-600 text-white rounded-2xl font-bold text-lg hover:bg-indigo-700 transition shadow-lg shadow-indigo-200">로그인</button>
            </form>
            <p class="text-center text-sm text-slate-400 mt-6">계정이 없으신가요?
                <button onclick="toggleRegister()" class="text-indigo-600 font-bold hover:underline">회원가입</button>
            </p>
            <p class="text-center text-sm text-slate-400 mt-3">
                <button onclick="showAuthPanel('recovery')" class="text-slate-600 font-bold hover:underline">회원정보 찾기</button>
            </p>
        </div>

        <div id="register-form" class="<?= $auth_panel === 'register' ? '' : 'hidden' ?> bg-white p-10 rounded-[2.5rem] shadow-2xl">
            <div class="text-center mb-8">
                <h2 class="text-2xl font-black text-slate-800">회원가입</h2>
                <p class="text-sm text-slate-400 mt-2">이메일과 휴대폰 인증 후 가입할 수 있어요.</p>
            </div>
            <form method="POST">
                <input type="text" name="reg_name" value="<?= e($form_values['reg_name']) ?>" placeholder="이름" class="w-full p-4 border rounded-2xl mb-4 outline-none focus:ring-2 focus:ring-indigo-500 bg-slate-50" minlength="2" required>
                <input type="text" name="reg_username" value="<?= e($form_values['reg_username']) ?>" placeholder="아이디 (4~20자, 영문/숫자/_)" class="w-full p-4 border rounded-2xl mb-4 outline-none focus:ring-2 focus:ring-indigo-500 bg-slate-50" pattern="[A-Za-z0-9_]{4,20}" required>
                <div class="grid grid-cols-[1fr_auto] gap-2 mb-3">
                    <input type="email" name="reg_email" value="<?= e($form_values['reg_email']) ?>" placeholder="이메일" class="w-full p-4 border rounded-2xl outline-none focus:ring-2 focus:ring-indigo-500 bg-slate-50" required>
                    <button name="send_reg_email_code" formnovalidate class="px-4 bg-indigo-50 text-indigo-600 rounded-2xl font-black text-sm hover:bg-indigo-100">메일인증</button>
                </div>
                <input type="text" name="reg_email_code" placeholder="이메일 인증번호 6자리" inputmode="numeric" maxlength="6" class="w-full p-4 border rounded-2xl mb-4 outline-none focus:ring-2 focus:ring-indigo-500 bg-slate-50" required>
                <div class="grid grid-cols-[1fr_auto] gap-2 mb-3">
                    <input type="tel" name="reg_phone" value="<?= e($form_values['reg_phone']) ?>" placeholder="전화번호 (예: 010-1234-5678)" class="w-full p-4 border rounded-2xl outline-none focus:ring-2 focus:ring-indigo-500 bg-slate-50" pattern="01[016789]-?\d{3,4}-?\d{4}" required>
                    <button name="send_reg_phone_code" formnovalidate class="px-4 bg-indigo-50 text-indigo-600 rounded-2xl font-black text-sm hover:bg-indigo-100">휴대폰인증</button>
                </div>
                <input type="text" name="reg_phone_code" placeholder="휴대폰 인증번호 6자리" inputmode="numeric" maxlength="6" class="w-full p-4 border rounded-2xl mb-4 outline-none focus:ring-2 focus:ring-indigo-500 bg-slate-50" required>
                <input type="password" name="reg_password" placeholder="비밀번호 (8~20자, 영문/숫자/특수문자 포함)" class="w-full p-4 border rounded-2xl mb-4 outline-none focus:ring-2 focus:ring-indigo-500 bg-slate-50" required>
                <input type="password" name="reg_password_confirm" placeholder="비밀번호 확인" class="w-full p-4 border rounded-2xl mb-2 outline-none focus:ring-2 focus:ring-indigo-500 bg-slate-50" required>
                <p class="text-xs text-slate-400 mb-6 leading-5">비밀번호는 8~20자이며 영문, 숫자, 특수문자를 각각 1개 이상 포함해야 합니다.</p>
                <button name="register" class="w-full py-4 bg-slate-800 text-white rounded-2xl font-bold text-lg hover:bg-slate-900 transition">가입하기</button>
            </form>
            <p class="text-center text-sm text-slate-400 mt-6">
                <button onclick="toggleRegister()" class="text-indigo-600 font-bold hover:underline">← 로그인으로</button>
            </p>
        </div>

        <div id="recovery-form" class="<?= $auth_panel === 'recovery' ? '' : 'hidden' ?> bg-white p-10 rounded-[2.5rem] shadow-2xl">
            <div class="text-center mb-8">
                <h2 class="text-2xl font-black text-slate-800">회원정보 찾기</h2>
                <p class="text-sm text-slate-400 mt-2">가입한 이메일 인증으로 아이디를 확인하고 비밀번호를 다시 설정할 수 있어요.</p>
            </div>
            <form method="POST">
                <div class="grid grid-cols-[1fr_auto] gap-2 mb-3">
                    <input type="email" name="find_email" value="<?= e($form_values['find_email']) ?>" placeholder="가입한 이메일" class="w-full p-4 border rounded-2xl outline-none focus:ring-2 focus:ring-indigo-500 bg-slate-50" required>
                    <button name="send_recovery_email_code" formnovalidate class="px-4 bg-indigo-50 text-indigo-600 rounded-2xl font-black text-sm hover:bg-indigo-100">메일인증</button>
                </div>
                <input type="text" name="recovery_email_code" placeholder="이메일 인증번호 6자리" inputmode="numeric" maxlength="6" class="w-full p-4 border rounded-2xl mb-4 outline-none focus:ring-2 focus:ring-indigo-500 bg-slate-50" required>

                <?php if ($recovery_result): ?>
                    <div class="bg-slate-50 border border-slate-100 rounded-2xl p-4 mb-4 text-sm">
                        <p class="font-black text-slate-800"><?= e($recovery_result['name'] ?: $recovery_result['username']) ?>님의 회원정보</p>
                        <p class="text-slate-500 mt-2">아이디: <span class="font-bold text-indigo-600"><?= e($recovery_result['username']) ?></span></p>
                        <p class="text-slate-500">이메일: <?= e($recovery_result['email']) ?></p>
                        <p class="text-slate-500">휴대폰: <?= e(maskPhone($recovery_result['phone'] ?? '')) ?></p>
                    </div>
                <?php endif; ?>

                <input type="password" name="recovery_new_password" placeholder="새 비밀번호 (선택)" class="w-full p-4 border rounded-2xl mb-4 outline-none focus:ring-2 focus:ring-indigo-500 bg-slate-50">
                <input type="password" name="recovery_new_password_confirm" placeholder="새 비밀번호 확인" class="w-full p-4 border rounded-2xl mb-2 outline-none focus:ring-2 focus:ring-indigo-500 bg-slate-50">
                <p class="text-xs text-slate-400 mb-6 leading-5">비밀번호 재설정이 필요 없으면 새 비밀번호 칸을 비워두고 확인하면 됩니다.</p>
                <button name="recover_account" class="w-full py-4 bg-slate-800 text-white rounded-2xl font-bold text-lg hover:bg-slate-900 transition">회원정보 확인하기</button>
            </form>
            <p class="text-center text-sm text-slate-400 mt-6">
                <button onclick="showAuthPanel('login')" class="text-indigo-600 font-bold hover:underline">← 로그인으로</button>
            </p>
        </div>
    </div>
</div>

<?php elseif ($current_trip): ?>
<!-- ===== 여행 상세 & 지출 내역 ===== -->
<nav class="bg-white/80 backdrop-blur-md sticky top-0 z-50 border-b p-4 flex justify-between items-center px-6">
    <div class="flex items-center gap-3">
        <a href="?" class="w-10 h-10 flex items-center justify-center rounded-full hover:bg-slate-100 transition">
            <i class="fa-solid fa-chevron-left text-lg"></i>
        </a>
        <span class="font-black text-xl tracking-tight text-indigo-600">TRAVELER</span>
    </div>
    <div class="flex items-center gap-4">
        <button type="button" onclick="document.getElementById('profile-modal').classList.remove('hidden')" class="flex items-center gap-2 text-sm font-bold text-slate-600 hover:text-indigo-600">
            <span class="w-9 h-9 rounded-full bg-indigo-100 text-indigo-600 flex items-center justify-center">
                <i class="fa-solid fa-user"></i>
            </span>
            <span><?= e($_SESSION['user_name'] ?? $_SESSION['user']) ?>님</span>
        </button>
        <a href="?logout=true" class="text-xs font-bold text-red-400 hover:text-red-600">LOGOUT</a>
    </div>
</nav>

<div class="max-w-2xl mx-auto py-8 px-4">
    <!-- 여행 요약 카드 -->
    <div class="bg-indigo-600 p-8 rounded-[2.5rem] text-white mb-6 shadow-xl shadow-indigo-200">
        <div class="flex justify-between items-start mb-6">
            <div>
                <span class="text-xs font-bold bg-white/20 px-3 py-1 rounded-full uppercase"><?= e($current_trip['country']) ?> · <?= e($current_trip['currency']) ?></span>
                <h2 class="text-2xl font-black mt-3"><?= e($current_trip['title']) ?></h2>
                <p class="text-indigo-200 text-sm mt-1">
                    <i class="fa-solid fa-plane-departure mr-1"></i><?= e($current_trip['airline'] ?: '항공사 미지정') ?>
                    <span class="ml-2 text-[11px] bg-white/15 px-2 py-1 rounded-full align-middle">수정 가능</span>
                    <?php if ($current_trip['flight_time']): ?> · <?= (($current_trip['trip_type'] ?? 'roundtrip') === 'oneway') ? '편도' : '가는편' ?> <?= date('m/d H:i', strtotime($current_trip['flight_time'])) ?><?php endif; ?>
                    <?php if (!empty($current_trip['return_flight_time'])): ?> · 오는편 <?= date('m/d H:i', strtotime($current_trip['return_flight_time'])) ?><?php endif; ?>
                </p>
            </div>
            <div class="flex items-center gap-3">
                <button type="button" onclick="document.getElementById('flight-modal').classList.remove('hidden')" class="text-white/70 hover:text-white text-xs">
                    <i class="fa-solid fa-pen-to-square"></i>
                </button>
                <a href="?del_trip=<?= (int)$current_trip['id'] ?>" onclick="return confirm('여행을 삭제하면 모든 지출도 삭제됩니다. 계속할까요?')" class="text-white/50 hover:text-white text-xs">
                    <i class="fa-solid fa-trash"></i>
                </a>
            </div>
        </div>
        <div class="grid grid-cols-2 gap-4">
            <div class="bg-white/10 rounded-2xl p-4">
                <p class="text-indigo-200 text-xs font-bold"><?= (($current_trip['trip_type'] ?? 'roundtrip') === 'oneway') ? '편도 항공권' : '왕복 항공권' ?></p>
                <p class="text-xl font-black mt-1"><?= number_format($current_trip['flight_price']) ?>원</p>
            </div>
            <div class="bg-white/10 rounded-2xl p-4">
                <p class="text-indigo-200 text-xs font-bold">내 부담 지출</p>
                <p class="text-xl font-black mt-1"><?= number_format($trip_total_krw) ?>원</p>
            </div>
        </div>
        <div class="mt-4 pt-4 border-t border-white/20 flex justify-between items-center">
            <span class="text-indigo-200 font-bold">총 여행 비용</span>
            <span class="text-2xl font-black"><?= number_format($current_trip['flight_price'] + $trip_total_krw) ?>원</span>
        </div>
    </div>

    <!-- 항공편 수정 모달 -->
    <div id="flight-modal" class="hidden fixed inset-0 modal-bg z-50 flex items-end md:items-center justify-center p-4">
        <div class="bg-white rounded-[2rem] p-8 w-full max-w-md shadow-2xl">
            <div class="flex justify-between items-center mb-6">
                <h3 class="text-xl font-black">항공편 수정</h3>
                <button type="button" onclick="document.getElementById('flight-modal').classList.add('hidden')" class="text-slate-400 hover:text-slate-600">
                    <i class="fa-solid fa-xmark text-xl"></i>
                </button>
            </div>
            <form method="POST">
                <input type="hidden" name="trip_id" value="<?= (int)$current_trip['id'] ?>">
                <input type="hidden" name="update_flight" value="1">
                <div class="mb-4">
                    <label class="block text-sm font-bold text-slate-400 mb-2">항공편 종류</label>
                    <div class="grid grid-cols-2 gap-2">
                        <label class="border rounded-2xl p-4 bg-slate-50 cursor-pointer">
                            <input type="radio" name="trip_type" value="roundtrip" <?= (($current_trip['trip_type'] ?? 'roundtrip') === 'roundtrip') ? 'checked' : '' ?> onclick="toggleReturnFields(this.value)" class="mr-2">
                            <span class="font-bold text-slate-700">왕복</span>
                        </label>
                        <label class="border rounded-2xl p-4 bg-slate-50 cursor-pointer">
                            <input type="radio" name="trip_type" value="oneway" <?= (($current_trip['trip_type'] ?? 'roundtrip') === 'oneway') ? 'checked' : '' ?> onclick="toggleReturnFields(this.value)" class="mr-2">
                            <span class="font-bold text-slate-700">편도</span>
                        </label>
                    </div>
                </div>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-bold text-slate-400 mb-2">항공사</label>
                        <input type="text" name="airline" value="<?= e($current_trip['airline']) ?>" placeholder="예: 대한항공, 아시아나, 비엣젯" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500">
                    </div>
                    <div class="grid grid-cols-2 gap-3">
                        <div>
                            <label class="block text-sm font-bold text-slate-400 mb-2"><?= (($current_trip['trip_type'] ?? 'roundtrip') === 'oneway') ? '편도 시간' : '가는편 시간' ?></label>
                            <input type="datetime-local" name="flight_time" value="<?= !empty($current_trip['flight_time']) ? date('Y-m-d\\TH:i', strtotime($current_trip['flight_time'])) : '' ?>" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500">
                        </div>
                        <div>
                            <label class="block text-sm font-bold text-slate-400 mb-2"><?= (($current_trip['trip_type'] ?? 'roundtrip') === 'oneway') ? '편도 금액 (KRW)' : '왕복 총 금액 (KRW)' ?></label>
                            <input type="number" name="flight_price" value="<?= intval($current_trip['flight_price']) ?>" placeholder="0" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500">
                        </div>
                    </div>
                    <div id="return-fields" class="mt-3 <?= (($current_trip['trip_type'] ?? 'roundtrip') === 'oneway') ? 'hidden' : '' ?>">
                        <div>
                            <label class="block text-sm font-bold text-slate-400 mb-2">오는편 시간</label>
                            <input type="datetime-local" name="return_flight_time" value="<?= !empty($current_trip['return_flight_time']) ? date('Y-m-d\\TH:i', strtotime($current_trip['return_flight_time'])) : '' ?>" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500">
                        </div>
                        <p class="text-xs text-slate-400 font-medium mt-2">편도로 저장했더라도 나중에 오는편 시간을 추가할 수 있어요.</p>
                    </div>
                    <button type="submit" class="w-full py-4 bg-indigo-600 text-white rounded-2xl font-bold text-lg hover:bg-indigo-700 transition">항공편 저장하기</button>
                </div>
            </form>
        </div>
    </div>

    <!-- 카테고리별 합계 -->
    <?php if ($expenses):
        $by_cat = [];
        foreach ($expenses as $exp) {
            $by_cat[$exp['category']] = ($by_cat[$exp['category']] ?? 0) + $exp['my_share_krw'];
        }
        arsort($by_cat);
    ?>
    <div class="grid grid-cols-3 gap-3 mb-6">
        <?php foreach ($by_cat as $cat => $amt): ?>
        <div class="bg-white rounded-2xl p-4 text-center border border-slate-100">
            <div class="w-10 h-10 <?= $category_colors[$cat] ?? 'bg-slate-100 text-slate-500' ?> rounded-xl flex items-center justify-center mx-auto mb-2">
                <i class="fa-solid <?= $category_icons[$cat] ?? 'fa-circle-dot' ?> text-sm"></i>
            </div>
            <p class="text-xs font-bold text-slate-400"><?= e($cat) ?></p>
            <p class="text-sm font-black text-slate-700"><?= number_format($amt) ?>원</p>
        </div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <!-- 지출 추가 버튼 -->
    <button onclick="document.getElementById('expense-modal').classList.remove('hidden')"
        class="w-full py-4 bg-white border-2 border-dashed border-indigo-200 text-indigo-500 rounded-2xl font-bold hover:bg-indigo-50 transition mb-6">
        <i class="fa-solid fa-plus mr-2"></i>지출 내역 추가
    </button>

    <!-- 지출 목록 -->
    <div class="space-y-3">
        <?php foreach ($expenses as $exp): ?>
        <div class="bg-white rounded-2xl p-5 flex items-center gap-4 border border-slate-100 shadow-sm">
            <div class="w-12 h-12 <?= $category_colors[$exp['category']] ?? 'bg-slate-100 text-slate-500' ?> rounded-xl flex items-center justify-center flex-shrink-0">
                <i class="fa-solid <?= $category_icons[$exp['category']] ?? 'fa-circle-dot' ?>"></i>
            </div>
            <div class="flex-1 min-w-0">
                <p class="font-bold text-slate-800 truncate"><?= e($exp['description']) ?></p>
                <p class="text-xs text-slate-400 font-medium"><?= e($exp['expense_date']) ?> · <?= e($exp['category']) ?></p>
            </div>
            <div class="text-right flex-shrink-0">
                <p class="font-black text-slate-800">내 부담 <?= number_format($exp['my_share_krw']) ?>원</p>
                <p class="text-xs text-slate-400">총 <?= number_format($exp['amount_krw']) ?>원</p>
                <p class="text-xs text-slate-400"><?= e($exp['paid_by'] ?: '미정') ?> 결제 · <?= intval($exp['participants']) ?>명</p>
            </div>
            <a href="?trip=<?= (int)$current_trip['id'] ?>&del_expense=<?= (int)$exp['id'] ?>" onclick="return confirm('삭제할까요?')" class="text-slate-200 hover:text-red-400 ml-2">
                <i class="fa-solid fa-xmark"></i>
            </a>
        </div>
        <?php endforeach; ?>

        <?php if (empty($expenses)): ?>
        <div class="text-center py-16 text-slate-300">
            <i class="fa-solid fa-receipt text-4xl mb-3 block"></i>
            <p class="font-bold">아직 지출 내역이 없어요</p>
        </div>
        <?php endif; ?>
    </div>
</div>

<!-- 지출 추가 모달 -->
<div id="expense-modal" class="hidden fixed inset-0 modal-bg z-50 flex items-end md:items-center justify-center p-4">
    <div class="bg-white rounded-[2rem] p-8 w-full max-w-md shadow-2xl">
        <div class="flex justify-between items-center mb-6">
            <h3 class="text-xl font-black">지출 추가</h3>
            <button onclick="document.getElementById('expense-modal').classList.add('hidden')" class="text-slate-400 hover:text-slate-600">
                <i class="fa-solid fa-xmark text-xl"></i>
            </button>
        </div>
        <form method="POST">
            <input type="hidden" name="trip_id" value="<?= (int)$current_trip['id'] ?>">
            <input type="hidden" name="currency" value="<?= e($current_trip['currency']) ?>">
            <input type="hidden" name="save_expense" value="1">

            <div class="grid grid-cols-3 gap-2 mb-5" id="cat-btns">
                <?php foreach ($category_icons as $cat => $icon): ?>
                <button type="button" onclick="selectCat('<?= e($cat) ?>')"
                    class="cat-btn p-3 rounded-xl border-2 border-slate-100 text-center hover:border-indigo-300 transition" data-cat="<?= e($cat) ?>">
                    <i class="fa-solid <?= $icon ?> text-slate-400 block mb-1"></i>
                    <span class="text-xs font-bold text-slate-500"><?= e($cat) ?></span>
                </button>
                <?php endforeach; ?>
            </div>
            <input type="hidden" name="category" id="sel_category" value="기타">

            <input type="text" name="description" placeholder="내용 (예: 쌀국수 점심)" class="w-full p-4 border rounded-2xl bg-slate-50 mb-4 outline-none focus:ring-2 focus:ring-indigo-500" required>

            <div class="grid grid-cols-2 gap-3 mb-4">
                <div>
                    <label class="text-xs font-bold text-slate-400 block mb-1">결제자</label>
                    <input type="text" name="paid_by" value="<?= e($_SESSION['user'] ?? '') ?>" placeholder="예: 나, 철수" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500">
                </div>
                <div>
                    <label class="text-xs font-bold text-slate-400 block mb-1">총 인원</label>
                    <input type="number" name="participants" value="1" min="1" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500">
                </div>
            </div>

            <div class="mb-4">
                <label class="flex items-center gap-2 text-sm font-bold text-slate-600">
                    <input type="checkbox" name="is_my_payment" value="1" class="w-4 h-4">
                    내가 전액 결제함 (N빵 안 함)
                </label>
            </div>

            <div class="grid grid-cols-2 gap-3 mb-4">
                <div>
                    <label class="text-xs font-bold text-slate-400 block mb-1">현지 금액 (<?= e($current_trip['currency']) ?>)</label>
                    <input type="number" step="0.01" name="amount_foreign" id="amount_foreign" placeholder="0"
                        class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500"
                        oninput="calcKrw()">
                </div>
                <div>
                    <label class="text-xs font-bold text-slate-400 block mb-1">원화 금액 (KRW)</label>
                    <input type="number" name="amount_krw" id="amount_krw" placeholder="0"
                        class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500"
                        oninput="calcForeign()" required>
                </div>
            </div>

            <div class="mb-6">
                <label class="text-xs font-bold text-slate-400 block mb-1">날짜</label>
                <input type="date" name="expense_date" value="<?= date('Y-m-d') ?>" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500" required>
            </div>

            <button type="submit" class="w-full py-4 bg-indigo-600 text-white rounded-2xl font-bold text-lg hover:bg-indigo-700 transition">저장하기</button>
        </form>
    </div>
</div>

<?php else: ?>
<!-- ===== 메인: 여행 목록 & 새 여행 생성 ===== -->
<nav class="bg-white/80 backdrop-blur-md sticky top-0 z-50 border-b p-4 flex justify-between items-center px-6">
    <span class="font-black text-xl tracking-tight text-indigo-600">TRAVELER</span>
    <div class="flex items-center gap-4">
        <button type="button" onclick="document.getElementById('profile-modal').classList.remove('hidden')" class="flex items-center gap-2 text-sm font-bold text-slate-600 hover:text-indigo-600">
            <span class="w-9 h-9 rounded-full bg-indigo-100 text-indigo-600 flex items-center justify-center">
                <i class="fa-solid fa-user"></i>
            </span>
            <span><?= e($_SESSION['user_name'] ?? $_SESSION['user']) ?>님</span>
        </button>
        <a href="?logout=true" class="text-xs font-bold text-red-400 hover:text-red-600">LOGOUT</a>
    </div>
</nav>

<div class="max-w-2xl mx-auto py-8 px-4">
    <!-- 새 여행 생성 폼 -->
    <div id="new-trip-section">
        <div id="step-1" class="step-content bg-white p-8 rounded-[2.5rem] shadow-sm border border-slate-100 mb-8">
            <h2 class="text-2xl font-black mb-6 text-slate-800">어디로 떠나시나요? ✈️</h2>
            <div class="space-y-5">
                <div>
                    <label class="block text-sm font-bold text-slate-400 mb-2">여행 목적지</label>
                    <select id="target_country" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500" onchange="updateCurrency()">
                        <option value="VN" data-curr="VND">베트남 (VND)</option>
                        <option value="JP" data-curr="JPY">일본 (JPY)</option>
                        <option value="CN" data-curr="CNY">중국 (CNY)</option>
                        <option value="US" data-curr="USD">미국 (USD)</option>
                        <option value="EU" data-curr="EUR">유럽 (EUR)</option>
                        <option value="TH" data-curr="THB">태국 (THB)</option>
                        <option value="PH" data-curr="PHP">필리핀 (PHP)</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm font-bold text-slate-400 mb-2">여행 제목</label>
                    <input type="text" id="trip_title" placeholder="예: 다낭 3박 4일 가족여행" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500">
                </div>
                <div class="p-5 bg-indigo-600 rounded-2xl text-white">
                    <p class="text-indigo-200 text-xs font-bold uppercase">Live Exchange Rate</p>
                    <h4 class="text-xl font-black mt-1" id="rate_info">로딩 중...</h4>
                    <p class="mt-2 text-sm font-medium bg-white/10 rounded-full px-4 py-2 inline-block" id="krw_value"></p>
                    <p class="text-xs text-indigo-300 mt-2" id="rate_source"></p>
                </div>
                <button onclick="nextStep(2)" class="w-full py-4 bg-indigo-600 text-white rounded-2xl font-bold text-lg hover:bg-indigo-700 transition shadow-lg shadow-indigo-100">다음 단계로</button>
            </div>
        </div>

        <div id="step-2" class="step-content hidden bg-white p-8 rounded-[2.5rem] shadow-sm border border-slate-100 mb-8">
            <button onclick="goBack()" class="text-slate-400 mb-4 hover:text-slate-600"><i class="fa-solid fa-chevron-left mr-1"></i> 이전</button>
            <h2 class="text-2xl font-black mb-6 text-slate-800">항공권 정보 입력 🎫</h2>
            <form method="POST">
                <input type="hidden" name="save_trip" value="1">
                <input type="hidden" name="country" id="form_country" value="VN">
                <input type="hidden" name="currency" id="form_currency" value="VND">
                <input type="hidden" name="trip_type" id="form_trip_type" value="roundtrip">
                <input type="hidden" name="trip_title" id="form_title">
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-bold text-slate-400 mb-2">항공사</label>
                        <input type="text" name="airline" placeholder="예: 대한항공, 아시아나, 비엣젯" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500">
                    </div>
                    <div>
                        <label class="block text-sm font-bold text-slate-400 mb-2">항공편 종류</label>
                        <div class="grid grid-cols-2 gap-2">
                            <button type="button" onclick="setTripType('roundtrip')" id="trip-type-roundtrip" class="trip-type-btn p-4 rounded-2xl border-2 border-indigo-500 bg-indigo-50 text-indigo-600 font-bold">왕복</button>
                            <button type="button" onclick="setTripType('oneway')" id="trip-type-oneway" class="trip-type-btn p-4 rounded-2xl border-2 border-slate-100 bg-slate-50 text-slate-500 font-bold">편도</button>
                        </div>
                    </div>
                    <div class="grid grid-cols-2 gap-3">
                        <div>
                            <label id="depart-time-label" class="block text-sm font-bold text-slate-400 mb-2">가는편 시간</label>
                            <input type="datetime-local" name="flight_time" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500">
                        </div>
                        <div>
                            <label id="depart-price-label" class="block text-sm font-bold text-slate-400 mb-2">왕복 총 금액 (KRW)</label>
                            <input type="number" name="flight_price" placeholder="0" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500">
                        </div>
                    </div>
                    <div id="create-return-fields" class="mt-3">
                        <div>
                            <label class="block text-sm font-bold text-slate-400 mb-2">오는편 시간</label>
                            <input type="datetime-local" name="return_flight_time" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500">
                        </div>
                        <p class="text-xs text-slate-400 font-medium mt-2">편도로 저장해도 상세 화면에서 나중에 오는편을 추가할 수 있어요.</p>
                    </div>
                    <input type="hidden" name="return_flight_price" value="0">
                    <button type="submit" class="w-full py-4 bg-black text-white rounded-2xl font-bold text-lg hover:bg-slate-800 transition mt-2">가계부 생성하기</button>
                </div>
            </form>
        </div>
    </div>

    <!-- 여행 목록 -->
    <?php if ($trips): ?>
    <h3 class="text-lg font-black text-slate-400 mb-4 uppercase tracking-wider">내 여행 기록</h3>
    <div class="space-y-4">
        <?php foreach ($trips as $trip): ?>
        <a href="?trip=<?= (int)$trip['id'] ?>" class="block bg-white p-6 rounded-[1.75rem] border border-slate-100 shadow-sm hover:shadow-md hover:border-indigo-200 transition">
            <div class="flex justify-between items-start">
                <div>
                    <span class="text-xs font-bold bg-indigo-50 text-indigo-500 px-2 py-1 rounded-full"><?= e($trip['country']) ?> · <?= e($trip['currency']) ?></span>
                    <h4 class="font-black text-slate-800 text-lg mt-2"><?= e($trip['title']) ?></h4>
                    <p class="text-sm text-slate-400 mt-1">
                        <i class="fa-solid fa-plane mr-1"></i><?= e($trip['airline'] ?: '항공사 미지정') ?>
                        <?php if ($trip['flight_time']): ?> · <?= (($trip['trip_type'] ?? 'roundtrip') === 'oneway') ? '편도' : '가는편' ?> <?= date('m/d', strtotime($trip['flight_time'])) ?><?php endif; ?>
                        <?php if (!empty($trip['return_flight_time'])): ?> · 오는편 <?= date('m/d', strtotime($trip['return_flight_time'])) ?><?php endif; ?>
                    </p>
                </div>
                <div class="text-right">
                    <p class="text-xs text-slate-400 font-bold">총 지출</p>
                    <p class="text-lg font-black text-indigo-600"><?= number_format($trip['flight_price'] + $trip['total_expense']) ?>원</p>
                </div>
            </div>
        </a>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>
</div>
<?php endif; ?>

<?php if (isset($_SESSION['user']) && $current_user_profile): ?>
<!-- ===== 프로필 모달 (로그인 상태에서만, 페이지 공통) ===== -->
<!-- [FIX] 모달을 모든 로그인 분기의 바깥(공통 위치)에 단 한 번만 배치 -->
<div id="profile-modal" class="hidden fixed inset-0 modal-bg z-50 flex items-end md:items-center justify-center p-4">
    <div class="bg-white rounded-[2rem] p-8 w-full max-w-lg shadow-2xl max-h-[90vh] overflow-y-auto">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h3 class="text-2xl font-black text-slate-800">내 프로필</h3>
                <p class="text-sm text-slate-400 mt-1">회원 정보 수정과 비밀번호 변경을 한 번에 관리할 수 있어요.</p>
            </div>
            <button type="button" onclick="document.getElementById('profile-modal').classList.add('hidden')" class="text-slate-400 hover:text-slate-600">
                <i class="fa-solid fa-xmark text-xl"></i>
            </button>
        </div>

        <?php if ($error): ?>
            <div class="bg-red-50 border border-red-200 text-red-600 p-4 rounded-2xl mb-4 text-sm font-bold"><?= e($error) ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="bg-green-50 border border-green-200 text-green-600 p-4 rounded-2xl mb-4 text-sm font-bold"><?= e($success) ?></div>
        <?php endif; ?>

        <div class="bg-slate-50 rounded-2xl p-5 mb-6 border border-slate-100">
            <div class="flex items-center gap-4">
                <div class="w-16 h-16 rounded-full bg-indigo-100 text-indigo-600 flex items-center justify-center text-2xl">
                    <i class="fa-solid fa-user"></i>
                </div>
                <div>
                    <p class="text-lg font-black text-slate-800"><?= e($current_user_profile['name'] ?: $current_user_profile['username']) ?></p>
                    <p class="text-sm text-slate-500">@<?= e($current_user_profile['username']) ?></p>
                    <p class="text-xs text-slate-400 mt-1">가입일 <?= date('Y.m.d', strtotime($current_user_profile['created_at'])) ?></p>
                </div>
            </div>
        </div>

        <form method="POST" class="space-y-4">
            <!-- [FIX] CSRF 토큰 포함 -->
            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="update_profile" value="1">

            <div>
                <label class="block text-sm font-bold text-slate-400 mb-2">이름</label>
                <input type="text" name="profile_name" value="<?= e($current_user_profile['name'] ?? '') ?>" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500" minlength="2" required>
            </div>
            <div>
                <label class="block text-sm font-bold text-slate-400 mb-2">아이디</label>
                <input type="text" name="profile_username" value="<?= e($current_user_profile['username'] ?? '') ?>" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500" pattern="[A-Za-z0-9_]{4,20}" required>
                <p class="text-xs text-slate-400 mt-2">아이디는 4~20자의 영문, 숫자, 밑줄(_)만 사용할 수 있어요.</p>
            </div>
            <div>
                <label class="block text-sm font-bold text-slate-400 mb-2">이메일</label>
                <input type="email" name="profile_email" value="<?= e($current_user_profile['email'] ?? '') ?>" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500" required>
            </div>
            <div>
                <label class="block text-sm font-bold text-slate-400 mb-2">전화번호</label>
                <input type="tel" name="profile_phone" value="<?= e($current_user_profile['phone'] ?? '') ?>" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500" pattern="01[016789]-?\d{3,4}-?\d{4}" required>
            </div>

            <div class="pt-4 border-t border-slate-100">
                <h4 class="text-sm font-black text-slate-700 mb-3">비밀번호 변경</h4>
                <div class="space-y-3">
                    <input type="password" name="current_password" placeholder="현재 비밀번호 (비밀번호를 바꿀 때만 입력)" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500">
                    <input type="password" name="new_password" placeholder="새 비밀번호" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500">
                    <input type="password" name="new_password_confirm" placeholder="새 비밀번호 확인" class="w-full p-4 border rounded-2xl bg-slate-50 outline-none focus:ring-2 focus:ring-indigo-500">
                    <p class="text-xs text-slate-400">새 비밀번호는 8~20자이며 영문, 숫자, 특수문자를 모두 포함해야 합니다.</p>
                </div>
            </div>

            <button type="submit" class="w-full py-4 bg-indigo-600 text-white rounded-2xl font-bold text-lg hover:bg-indigo-700 transition">회원 정보 저장하기</button>
        </form>
    </div>
</div>
<?php endif; ?>

<script>
let currentStep = 1;
let liveRates = {};
let selectedCurrency = 'VND';

// [FIX] 현재 여행 통화 (PHP에서 JS로 안전하게 전달)
const TRIP_CURRENCY = <?= json_encode($current_trip['currency'] ?? '') ?>;

// 환율 실시간 로드
async function loadRates() {
    try {
        const res  = await fetch('https://api.exchangerate-api.com/v4/latest/KRW');
        const data = await res.json();
        liveRates  = data.rates;
        const srcEl = document.getElementById('rate_source');
        if (srcEl) srcEl.innerText = '실시간 환율 · ' + new Date().toLocaleTimeString('ko-KR');
        updateCurrency();
    } catch(e) {
        // 오프라인 폴백
        liveRates = { VND: 1/0.055, JPY: 1/9.1, CNY: 1/189, USD: 1/1355, EUR: 1/1510, THB: 1/37, PHP: 1/24 };
        const srcEl = document.getElementById('rate_source');
        if (srcEl) srcEl.innerText = '오프라인 기준 환율';
        updateCurrency();
    }
}

function updateCurrency() {
    const sel = document.getElementById('target_country');
    if (!sel) return;
    const curr = sel.options[sel.selectedIndex].getAttribute('data-curr');
    selectedCurrency = curr;
    const ratePerKrw = liveRates[curr];
    if (!ratePerKrw) return;
    const krwPerOne = (1 / ratePerKrw).toFixed(2);
    document.getElementById('rate_info').innerText  = `1 ${curr} = ${Number(krwPerOne).toLocaleString()} 원`;
    const foreign10k = Math.round(10000 * ratePerKrw).toLocaleString();
    document.getElementById('krw_value').innerText  = `10,000원 ≒ ${foreign10k} ${curr}`;
}

function selectCat(cat) {
    document.getElementById('sel_category').value = cat;
    document.querySelectorAll('.cat-btn').forEach(btn => {
        const active = btn.dataset.cat === cat;
        btn.classList.toggle('border-indigo-500', active);
        btn.classList.toggle('bg-indigo-50',      active);
        btn.classList.toggle('border-slate-100',  !active);
    });
}

function setTripType(type) {
    const input          = document.getElementById('form_trip_type');
    const returnFields   = document.getElementById('create-return-fields');
    const departTimeLbl  = document.getElementById('depart-time-label');
    const departPriceLbl = document.getElementById('depart-price-label');
    const roundtripBtn   = document.getElementById('trip-type-roundtrip');
    const onewayBtn      = document.getElementById('trip-type-oneway');

    if (!input) return;
    input.value = type;

    if (returnFields) {
        returnFields.classList.remove('hidden');
        if (type === 'oneway') {
            const ri = returnFields.querySelector('input[name="return_flight_time"]');
            if (ri) ri.value = '';
        }
    }
    if (departTimeLbl)  departTimeLbl.innerText  = type === 'oneway' ? '편도 시간'    : '가는편 시간';
    if (departPriceLbl) departPriceLbl.innerText = type === 'oneway' ? '편도 금액 (KRW)' : '왕복 총 금액 (KRW)';

    const active   = 'trip-type-btn p-4 rounded-2xl border-2 font-bold border-indigo-500 bg-indigo-50 text-indigo-600';
    const inactive = 'trip-type-btn p-4 rounded-2xl border-2 font-bold border-slate-100 bg-slate-50 text-slate-500';
    if (roundtripBtn) roundtripBtn.className = type === 'roundtrip' ? active : inactive;
    if (onewayBtn)    onewayBtn.className    = type === 'oneway'    ? active : inactive;
}

// [FIX] 항공편 수정 모달 왕복/편도 토글
function toggleReturnFields(type) {
    const wrap = document.getElementById('return-fields');
    if (!wrap) return;
    wrap.classList.toggle('hidden', type === 'oneway');
}

// [FIX] 상세 페이지에서 liveRates 사용 — TRIP_CURRENCY 기준
function calcKrw() {
    const foreign    = parseFloat(document.getElementById('amount_foreign').value) || 0;
    const ratePerKrw = liveRates[TRIP_CURRENCY];
    if (ratePerKrw && foreign > 0) {
        document.getElementById('amount_krw').value = Math.round(foreign / ratePerKrw);
    }
}

function calcForeign() {
    const krw        = parseFloat(document.getElementById('amount_krw').value) || 0;
    const ratePerKrw = liveRates[TRIP_CURRENCY];
    if (ratePerKrw && krw > 0) {
        document.getElementById('amount_foreign').value = (krw * ratePerKrw).toFixed(0);
    }
}

function nextStep(step) {
    if (step === 2) {
        const sel = document.getElementById('target_country');
        document.getElementById('form_country').value  = sel ? sel.value : 'VN';
        document.getElementById('form_currency').value = selectedCurrency;
        document.getElementById('form_title').value    = document.getElementById('trip_title').value || '새로운 여정';
    }
    document.querySelectorAll('.step-content').forEach(el => el.classList.add('hidden'));
    document.getElementById(`step-${step}`).classList.remove('hidden');
    currentStep = step;
}

function goBack() {
    document.querySelectorAll('.step-content').forEach(el => el.classList.add('hidden'));
    document.getElementById('step-1').classList.remove('hidden');
    currentStep = 1;
}

function toggleRegister() {
    const registerHidden = document.getElementById('register-form').classList.contains('hidden');
    showAuthPanel(registerHidden ? 'register' : 'login');
}

function showAuthPanel(panel) {
    ['login', 'register', 'recovery'].forEach(name => {
        const el = document.getElementById(`${name}-form`);
        if (el) el.classList.toggle('hidden', name !== panel);
    });
}

// [FIX] 프로필 수정 후 성공 메시지가 있으면 모달 자동 오픈
window.onload = () => {
    loadRates(); // 모든 페이지에서 환율 로드
    selectCat && selectCat('기타');
    setTripType('roundtrip');

    <?php if ($success && isset($_SESSION['user'])): ?>
    const pm = document.getElementById('profile-modal');
    if (pm) pm.classList.remove('hidden');
    <?php endif; ?>
};
</script>
</body>
</html>
