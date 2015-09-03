<?php
/**
 * Plugin Name: Email Signin
 * Plugin URI: trepmal.com
 * Description: Bypass typical user/pass login with username/check-email/click-link sign in
 * Version: 0.1.0
 * Author: Kailey Lampert
 * Author URI: kaileylampert.com
 * License: GPLv2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 * TextDomain: email-signin
 * DomainPath:
 * Network:
 */

$email_signin = new Email_Signin();

class Email_Signin {

	/**
	 * hook in
	 */
	function __construct() {
		add_action( 'login_form',   array( $this, 'login_form' ) );
		add_filter( 'authenticate', array( $this, 'authenticate' ), 20, 3 );
	}

	/**
	 * Some js to remove the password field
	 */
	function login_form() {
		?>
<script>
Element.prototype.remove = function() {
    this.parentElement.removeChild(this);
}
NodeList.prototype.remove = HTMLCollection.prototype.remove = function() {
    for(var i = this.length - 1; i >= 0; i--) {
        if(this[i] && this[i].parentElement) {
            this[i].parentElement.removeChild(this[i]);
        }
    }
}
userPass = document.getElementById('user_pass').parentNode;
userPass.remove();
</script>
		<?php
	}

	/**
	 * 1. verify sign in code from email link
	 * 2. send email on sign in attempt
	 */
	function authenticate( $user, $username, $password ) {

		// if code is provided, check it
		if ( isset( $_REQUEST['code'] ) ) {

			// valid user?
			$user = get_user_by( 'id', $_REQUEST['user'] );
			if ( ! $user ) {
				$error = new WP_Error();
				$error->add( 'no_user', __( 'user not found', 'email-signin' ) );
				return $error;
			}

			//
			$saved_code  = get_user_meta( $_REQUEST['user'], 'signin_code', true );
			$saved_valid = get_user_meta( $_REQUEST['user'], 'signin_valid', true );

			// if empty, bail
			if ( empty( $saved_code ) || empty( $saved_valid ) ) {
				$error = new WP_Error();
				$error->add( 'invalid_attempt', __( 'invalid attempt', 'email-signin' ) );
				return $error;
			}

			// expired?
			if ( $saved_valid < time() ) {
				$error = new WP_Error();
				$error->add( 'code_expired', __( 'code expired', 'email-signin' ) );
				return $error;
			}

			// match?
			if ( $saved_code != $_REQUEST['code'] ) {
				$error = new WP_Error();
				$error->add( 'code_mismatch', __( 'code mismatch', 'email-signin' ) );
				return $error;
			}

			// we're clear, but expire that code first
			update_user_meta( $_REQUEST['user'], 'signin_valid', '00' );

			return $user;

		}

		if ( is_email( $username ) ) {
			$user_obj = get_user_by( 'email', $username );
			if ( $user_obj ) $username = $user_obj->user_login;
		} else {
			$user_obj = get_user_by( 'login', $username );
		}

		// if user doesn't exist, just bail
		if ( ! $user_obj ) {
			return wp_authenticate_username_password( $user, $username, $password );
		}

		// generate code and expiration
		$code = substr( md5( time() . rand() . site_url() ), 0, 16 );
		$valid = strtotime( '+10 minutes' );

		// save code/expiration
		update_user_meta( $user_obj->ID, 'signin_code', $code );
		update_user_meta( $user_obj->ID, 'signin_valid', $valid );

		// send sign-in link
		$link = add_query_arg( array(
			'action' => 'login',
			'user'   => $user_obj->ID,
			'code'   => $code
		), site_url('wp-login.php') );
		$body = sprintf( __( "Click link to sign in\n%s", 'email-signin' ), $link );
		wp_mail( $user_obj->user_email, __( 'Your sign-in link.', 'email-signin' ), $body );

		// tell user to check their email
		$error = new WP_Error();
		$error->add( 'email_sent', __( 'Please check your email and click the link to sign in.' , 'email-signin' ) );
		return $error;
	}

}