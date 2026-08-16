<?php
/**
 * Synthetic SAFE sample plugin -- written for wp-hook-guard tests only.
 * Same shapes as the vulnerable fixture, but each handler is properly guarded.
 */

// Authenticated AJAX: nonce + capability check before the state change.
add_action( 'wp_ajax_sg_save_settings', 'sg_save_settings' );
function sg_save_settings() {
	check_ajax_referer( 'sg_save', 'nonce' );
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( 'forbidden', 403 );
	}
	update_option( 'sg_setting', sanitize_text_field( $_POST['value'] ) );
	wp_send_json_success();
}

// admin-post: admin referer + capability check.
add_action( 'admin_post_sg_update', 'sg_update' );
function sg_update() {
	check_admin_referer( 'sg_update_action' );
	if ( ! current_user_can( 'edit_others_posts' ) ) {
		wp_die( 'nope' );
	}
	wp_update_post( array( 'ID' => intval( $_POST['id'] ) ) );
}

// REST route guarded by a real permission_callback.
add_action( 'rest_api_init', 'sg_routes' );
function sg_routes() {
	register_rest_route(
		'sg/v1',
		'/settings',
		array(
			'methods'             => 'POST',
			'callback'            => 'sg_rest_update',
			'permission_callback' => function () {
				return current_user_can( 'manage_options' );
			},
		)
	);
}
function sg_rest_update( $request ) {
	update_option( 'sg_data', $request->get_param( 'data' ) );
	return array( 'ok' => true );
}
