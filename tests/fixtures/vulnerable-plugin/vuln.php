<?php
/**
 * Synthetic VULNERABLE sample plugin -- written for wp-hook-guard tests only.
 * Do not deploy. Every handler below is deliberately missing an access control
 * check to exercise the scanner.
 */

// 1) Unauthenticated AJAX that writes an option -> broken access control.
add_action( 'wp_ajax_nopriv_vg_save_settings', 'vg_save_settings' );
add_action( 'wp_ajax_vg_save_settings', 'vg_save_settings' );
function vg_save_settings() {
	$value = $_POST['value'];
	update_option( 'vg_setting', $value );   // no current_user_can, no nonce
	wp_send_json_success();
}

// 2) Unauthenticated admin-post that deletes rows -> broken access control.
add_action( 'admin_post_nopriv_vg_delete', 'vg_delete_handler' );
function vg_delete_handler() {
	global $wpdb;
	$id = intval( $_GET['id'] );
	$wpdb->query( "DELETE FROM {$wpdb->prefix}vg_items WHERE id = $id" );
}

// 3) init handler that reads $_GET and discloses a stored secret to anyone.
add_action( 'init', 'vg_maybe_export' );
function vg_maybe_export() {
	if ( isset( $_GET['vg_export'] ) ) {
		$config = get_option( 'vg_secret_config' );
		echo wp_json_encode( $config );
		exit;
	}
}

// 4) REST route that is public (permission_callback __return_true) and destructive.
add_action( 'rest_api_init', 'vg_register_routes' );
function vg_register_routes() {
	register_rest_route(
		'vg/v1',
		'/wipe',
		array(
			'methods'             => 'POST',
			'callback'            => 'vg_rest_wipe',
			'permission_callback' => '__return_true',
		)
	);
}
function vg_rest_wipe( $request ) {
	delete_option( 'vg_data' );
	return array( 'ok' => true );
}
