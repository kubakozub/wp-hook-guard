<?php
/**
 * REST edge cases: a route missing permission_callback entirely (public/bad),
 * and a route guarded by a *named* permission function.
 */

add_action( 'rest_api_init', 'rc_routes' );
function rc_routes() {

	// No permission_callback key at all -> publicly reachable.
	register_rest_route(
		'rc/v1',
		'/open',
		array(
			'methods'  => 'GET',
			'callback' => 'rc_open',
		)
	);

	// Guarded by a named permission function that checks a capability.
	register_rest_route(
		'rc/v1',
		'/closed',
		array(
			'methods'             => 'POST',
			'callback'            => 'rc_closed',
			'permission_callback' => 'rc_can_manage',
		)
	);
}

function rc_open( $request ) {
	return get_option( 'rc_public_data' );
}

function rc_closed( $request ) {
	update_option( 'rc_data', $request->get_param( 'v' ) );
	return true;
}

function rc_can_manage() {
	return current_user_can( 'manage_options' );
}
