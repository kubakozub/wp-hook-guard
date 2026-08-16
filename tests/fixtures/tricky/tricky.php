<?php
/**
 * Exercises the lexer: hook-like text inside comments and strings MUST NOT be
 * treated as real registrations. Only the last add_action() is real.
 */

// add_action( 'wp_ajax_nopriv_commented_out', 'ghost_one' );

$example = "add_action( 'wp_ajax_nopriv_in_string', 'ghost_two' )";

/*
 * add_action( 'wp_ajax_nopriv_block_comment', 'ghost_three' );
 */

# add_action( 'wp_ajax_nopriv_hash_comment', 'ghost_four' );

add_action( 'wp_ajax_nopriv_real_one', 'tricky_real' );
function tricky_real() {
	echo 'hello';
}
