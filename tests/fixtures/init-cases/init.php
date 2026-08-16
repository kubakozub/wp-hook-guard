<?php
/**
 * init-family gating: a benign reader (no sink) must NOT be reported, while a
 * reader that performs a sensitive write MUST be reported.
 */

// Benign: reads input but only branches / renders. Should be filtered out.
add_action( 'init', 'ic_benign' );
function ic_benign() {
	if ( isset( $_GET['ic_lang'] ) ) {
		define( 'IC_LANG', 'x' );
	}
}

// Sensitive: reads input and updates an option unauthenticated. Reported.
add_action( 'init', 'ic_apply' );
function ic_apply() {
	if ( ! empty( $_POST['ic_value'] ) ) {
		update_option( 'ic_value', $_POST['ic_value'] );
	}
}

// admin_init fires for any logged-in user (incl. Subscriber): authenticated.
add_action( 'admin_init', 'ic_admin_apply' );
function ic_admin_apply() {
	if ( isset( $_GET['ic_reset'] ) ) {
		delete_option( 'ic_value' );
	}
}
