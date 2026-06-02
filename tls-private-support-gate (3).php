<?php
/**
 * Plugin Name: TLS Private Support Gate (WP Fusion Edition)
 * Description: Protects /private-support/ using WP Fusion synced GoHighLevel tags. Boots Intercom as verified user.
 * Version: 2.1.0 (WP Fusion Edition)
 * Author: Angelo Gabriel M. De Guzman
 */

if (!defined("ABSPATH")) exit;

define("TLS_PSG_REQUIRED_TAG",  "private_support");
define("TLS_PSG_WPF_TAGS_META_KEY", "wpf_tags");
define("TLS_PSG_COOKIE",        "tls_private_support_access");
define("TLS_PSG_INACTIVITY_TIMEOUT", 15 * 60);
define("TLS_PSG_DEBUG",         true);

// IMPORTANT: Replace these with your actual credentials before use
define("TLS_INTERCOM_APP_ID", "YOUR_INTERCOM_APP_ID");
define("TLS_INTERCOM_IDENTITY_SECRET", "YOUR_INTERCOM_IDENTITY_SECRET");

define("TLS_PSG_LOGO_URL", "YOUR_LOGO_URL_HERE");
define("TLS_PSG_ACCENT", "#A51C30");

// ====================== DEBUG LOGGING ======================
function tls_psg_log($message) {
    if (TLS_PSG_DEBUG) { error_log("[TLS PSG WPF] " . $message); }
}

// ====================== WP FUSION TAG HELPERS ======================
function tls_psg_get_wpf_available_tags() {
    return get_option("wpf_available_tags", []);
}

function tls_psg_find_tag_id($tag_name) {
    $available_tags = tls_psg_get_wpf_available_tags();
    foreach ($available_tags as $tag_id => $tag_label) {
        if (strtolower($tag_label) === strtolower($tag_name)) return $tag_id;
    }
    $search_variations = [
        $tag_name, str_replace("_", " ", $tag_name),
        str_replace(" ", "_", $tag_name), str_replace("-", " ", $tag_name),
        str_replace(" ", "-", $tag_name)
    ];
    foreach ($available_tags as $tag_id => $tag_label) {
        foreach ($search_variations as $variation) {
            if (stripos($tag_label, $variation) !== false) return $tag_id;
        }
    }
    return null;
}

function tls_psg_user_has_tag($user_id, $required_tag) {
    tls_psg_log("TAG CHECK - User ID: " . $user_id . " | Tag: " . $required_tag);
    $user_tag_ids = get_user_meta($user_id, TLS_PSG_WPF_TAGS_META_KEY, true);
    if (!empty($user_tag_ids) && is_array($user_tag_ids)) {
        $required_tag_id = tls_psg_find_tag_id($required_tag);
        if ($required_tag_id && in_array($required_tag_id, $user_tag_ids)) {
            tls_psg_log("SUCCESS: User has tag");
            return true;
        }
    }
    if (function_exists("wp_fusion")) {
        $wpf_tags = wp_fusion()->user->get_tags($user_id);
        if (!empty($wpf_tags)) {
            $required_tag_id = tls_psg_find_tag_id($required_tag);
            if ($required_tag_id && in_array($required_tag_id, $wpf_tags)) {
                tls_psg_log("SUCCESS: User has tag (WPF function)");
                return true;
            }
        }
    }
    tls_psg_log("FAILED: User does not have required tag");
    return false;
}

function tls_psg_get_user_tag_names($user_id) {
    $user_tag_ids = get_user_meta($user_id, TLS_PSG_WPF_TAGS_META_KEY, true);
    if (empty($user_tag_ids) || !is_array($user_tag_ids)) return [];
    $available_tags = tls_psg_get_wpf_available_tags();
    $tag_names = [];
    foreach ($user_tag_ids as $tag_id) {
        if (isset($available_tags[$tag_id])) $tag_names[] = $available_tags[$tag_id];
    }
    return $tag_names;
}

// ====================== ROUTE CHECK ======================
function tls_psg_is_private_support_request() {
    if (is_admin()) return false;
    $uri  = isset($_SERVER["REQUEST_URI"]) ? (string) $_SERVER["REQUEST_URI"] : "";
    $path = (string) parse_url($uri, PHP_URL_PATH);
    return (strpos($path, "/private-support") === 0);
}

// ====================== COOKIE SECURITY ======================
function tls_psg_make_cookie_value($email, $user_id) {
    $data = ["email" => strtolower(trim($email)), "user_id" => (int) $user_id,
             "created" => time(), "last_active" => time(), "rand" => bin2hex(random_bytes(8))];
    $json = json_encode($data);
    $sig  = hash_hmac("sha256", $json, wp_salt("auth"));
    return base64_encode($json . "||" . $sig);
}

function tls_psg_parse_cookie_value($cookie) {
    if (empty($cookie)) return false;
    $decoded = base64_decode($cookie, true);
    if (!$decoded) return false;
    $parts = explode("||", $decoded);
    if (count($parts) !== 2) return false;
    $data = json_decode($parts[0], true);
    if (!$data || !isset($data["email"], $data["user_id"], $data["last_active"], $data["rand"])) return false;
    $expected_sig = hash_hmac("sha256", $parts[0], wp_salt("auth"));
    if (!hash_equals($expected_sig, $parts[1])) return false;
    if (time() - $data["last_active"] > TLS_PSG_INACTIVITY_TIMEOUT) {
        tls_psg_log("Cookie expired due to inactivity");
        return false;
    }
    return $data;
}

function tls_psg_clear_cookie() {
    setcookie(TLS_PSG_COOKIE, "", time() - 86400, "/", "", is_ssl(), true);
    if (isset($_COOKIE[TLS_PSG_COOKIE])) unset($_COOKIE[TLS_PSG_COOKIE]);
    if (session_status() !== PHP_SESSION_ACTIVE) @session_start();
    $_SESSION = [];
    @session_destroy();
}

function tls_psg_has_valid_cookie() {
    if (empty($_COOKIE[TLS_PSG_COOKIE])) return false;
    $parsed = tls_psg_parse_cookie_value(wp_unslash($_COOKIE[TLS_PSG_COOKIE]));
    if (!$parsed) { tls_psg_clear_cookie(); return false; }
    $user = get_user_by("id", $parsed["user_id"]);
    if (!$user) { tls_psg_clear_cookie(); return false; }
    if (!tls_psg_user_has_tag($user->ID, TLS_PSG_REQUIRED_TAG)) { tls_psg_clear_cookie(); return false; }
    return true;
}

function tls_psg_set_cookie($email) {
    $user = get_user_by("email", $email);
    if (!$user) return false;
    tls_psg_clear_cookie();
    $value = tls_psg_make_cookie_value($email, $user->ID);
    $result = setcookie(TLS_PSG_COOKIE, $value, ["expires" => 0, "path" => "/",
        "domain" => "", "secure" => is_ssl(), "httponly" => true, "samesite" => "Strict"]);
    $_COOKIE[TLS_PSG_COOKIE] = $value;
    return $result;
}

// ====================== PAGE GUARD ======================
add_action("template_redirect", "tls_psg_guard_private_support_page", 0);

function tls_psg_guard_private_support_page() {
    if (!tls_psg_is_private_support_request()) return;
    if (current_user_can("manage_options")) return;
    if (!defined("DONOTCACHEPAGE")) define("DONOTCACHEPAGE", true);
    nocache_headers();

    $message = "";
    $current_email = null;

    if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["tls_psg_email"])) {
        if (!isset($_POST["tls_psg_nonce"]) || !wp_verify_nonce($_POST["tls_psg_nonce"], "tls_psg_gate")) {
            $message = "Security check failed. Please try again.";
        } else {
            $submitted_email = sanitize_email(wp_unslash($_POST["tls_psg_email"]));
            $current_email = $submitted_email;
            tls_psg_clear_cookie();
            $user = $submitted_email ? get_user_by("email", $submitted_email) : false;
            if (!$user) {
                $message = "No user found with that email address.";
            } elseif (!tls_psg_user_has_tag($user->ID, TLS_PSG_REQUIRED_TAG)) {
                $message = "Your account does not currently have access to private support. Please contact hello@taxlienschool.com for assistance.";
            } else {
                if (tls_psg_set_cookie($submitted_email)) {
                    echo tls_psg_render_success_page($submitted_email);
                    exit;
                } else {
                    $message = "Authentication successful but session failed. Please try again.";
                }
            }
        }
    }

    if (!$current_email) {
        if (tls_psg_has_valid_cookie()) return;
        if (is_user_logged_in()) {
            $uid  = get_current_user_id();
            $user = wp_get_current_user();
            if ($uid && tls_psg_user_has_tag($uid, TLS_PSG_REQUIRED_TAG)) {
                tls_psg_set_cookie($user->user_email);
                return;
            }
        }
    }

    status_header(200);
    echo tls_psg_render_gate($message);
    exit;
}

// ====================== SUCCESS PAGE ======================
function tls_psg_render_success_page($email) {
    $logo = esc_url(TLS_PSG_LOGO_URL);
    $accent = TLS_PSG_ACCENT;
    $redirect_url = home_url("/private-support/");
    $safe_email = esc_html($email);
    return <<<HTML
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access Granted</title>
<style>body{font-family:system-ui;background:#f6f7f8;margin:0}.wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:18px}.card{background:#fff;padding:26px;border-radius:16px;max-width:480px;width:100%;box-shadow:0 10px 30px rgba(0,0,0,.08)}.card:before{content:"";display:block;height:6px;background:$accent;margin:-26px -26px 20px;border-radius:16px 16px 0 0}.logo{display:block;margin:0 auto 14px;width:200px}.success-icon{text-align:center;font-size:48px;margin:20px 0;color:#4CAF50}.msg{background:#e8f5e9;padding:15px;border-radius:10px;margin-bottom:20px;text-align:center}.spinner{border:4px solid #f3f3f3;border-top:4px solid $accent;border-radius:50%;width:40px;height:40px;animation:spin 1s linear infinite;margin:10px auto}@keyframes spin{to{transform:rotate(360deg)}}</style>
</head><body><div class="wrap"><div class="card">
<img src="$logo" class="logo" alt="Logo">
<h2 style="text-align:center">Access Granted</h2>
<div class="success-icon">✓</div>
<div class="msg"><p>Welcome, <strong>$safe_email</strong>!</p><p>Redirecting you to support...</p></div>
<div class="spinner"></div>
<script>setTimeout(function(){window.location.href="$redirect_url?verified="+encodeURIComponent("$safe_email")+"&t="+Date.now();},1500);</script>
</div></div></body></html>
HTML;
}

// ====================== GATE UI ======================
function tls_psg_render_gate($message) {
    $nonce  = wp_nonce_field("tls_psg_gate", "tls_psg_nonce", true, false);
    $msg    = $message ? "<div class='msg'>" . esc_html($message) . "</div>" : "";
    $logo   = esc_url(TLS_PSG_LOGO_URL);
    $accent = TLS_PSG_ACCENT;
    return <<<HTML
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Private Support Access</title>
<style>body{font-family:system-ui;background:#f6f7f8;margin:0}.wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:18px}.card{background:#fff;padding:26px;border-radius:16px;max-width:480px;width:100%;box-shadow:0 10px 30px rgba(0,0,0,.08)}.card:before{content:"";display:block;height:6px;background:$accent;margin:-26px -26px 20px;border-radius:16px 16px 0 0}.logo{display:block;margin:0 auto 14px;width:200px}.msg{background:#fff1f1;padding:12px;border-radius:10px;margin-bottom:16px;border-left:4px solid #ff5252}input,button{padding:14px;border-radius:10px;border:1px solid #ddd;font-size:16px;box-sizing:border-box}button{background:$accent;color:#fff;border:0;font-weight:700;cursor:pointer}.row{display:flex;gap:10px}.row input{flex:1}.info{background:#e3f2fd;padding:12px;border-radius:10px;margin-top:20px;border-left:4px solid #2196F3;font-size:14px}</style>
</head><body><div class="wrap"><div class="card">
<img src="$logo" class="logo" alt="Logo">
<h2 style="text-align:center">Private Support</h2>
<p style="text-align:center;opacity:.8">Enter your account email to continue.</p>
$msg
<form method="post" autocomplete="off">$nonce
<div class="row">
<input type="email" name="tls_psg_email" required placeholder="you@example.com" autofocus>
<button type="submit">Continue</button>
</div></form>
<div class="info"><strong>Note:</strong> This area is for enrolled students only. Enter the email associated with your enrollment.</div>
</div></div></body></html>
HTML;
}

// ====================== INTERCOM BOOT ======================
add_action("wp_footer", function () {
    if (!tls_psg_is_private_support_request()) return;
    if (empty($_COOKIE[TLS_PSG_COOKIE])) return;
    $parsed = tls_psg_parse_cookie_value(wp_unslash($_COOKIE[TLS_PSG_COOKIE]));
    if (!$parsed) return;
    $user = get_user_by("id", $parsed["user_id"]);
    if (!$user || !tls_psg_user_has_tag($user->ID, TLS_PSG_REQUIRED_TAG)) return;
    $intercom_user_id = "wp_" . $user->ID;
    $user_hash = hash_hmac("sha256", $intercom_user_id, TLS_INTERCOM_IDENTITY_SECRET);
    $app_id = TLS_INTERCOM_APP_ID;
    $email  = esc_js(strtolower($user->user_email));
    $name   = esc_js($user->display_name);
    ?>
    <script>
    window.intercomSettings = {
        app_id: "<?php echo esc_js($app_id); ?>",
        user_id: "<?php echo esc_js($intercom_user_id); ?>",
        email: "<?php echo $email; ?>",
        name: "<?php echo $name; ?>",
        user_hash: "<?php echo esc_js($user_hash); ?>"
    };
    (function(){var w=window,ic=w.Intercom;if(typeof ic==="function"){ic("reattach_activator");ic("update",w.intercomSettings);}else{var i=function(){i.c(arguments)};i.q=[];i.c=function(args){i.q.push(args)};w.Intercom=i;var s=document.createElement("script");s.async=true;s.src="https://widget.intercom.io/widget/<?php echo esc_js($app_id); ?>";document.head.appendChild(s);}})();
    </script>
    <?php
}, 20);

// ====================== CLEANUP ON LOGOUT ======================
add_action("wp_logout", function() { tls_psg_clear_cookie(); });
