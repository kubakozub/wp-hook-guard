<?php
/**
 * Synthetic class-based sample plugin -- exercises [$this, 'method'] resolution
 * and an intentionally unresolvable (dynamic) callback.
 */

class VG_Class_Plugin {

	public function __construct() {
		// Unauthenticated -> method resolved via $this; writes user meta.
		add_action( 'wp_ajax_nopriv_vgc_ping', array( $this, 'ping' ) );

		// Authenticated, but properly guarded.
		add_action( 'wp_ajax_vgc_secure', array( $this, 'secure' ) );

		// Dynamic/indirect callback -> should be reported as UNKNOWN.
		add_action( 'wp_ajax_nopriv_vgc_dyn', $this->callback );
	}

	public function ping() {
		$value = $_REQUEST['value'];
		update_user_meta( get_current_user_id(), 'vgc_last', $value );
	}

	public function secure() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		check_ajax_referer( 'vgc_secure' );
		delete_option( 'vgc_data' );
	}
}

new VG_Class_Plugin();
