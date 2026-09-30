<?php
/**
 * Plugin Name: DBExp Lab - INTENTIONALLY VULNERABLE
 * Description: Adds a deliberately SQL-injectable endpoint so the detector has something to
 *              detect. LAB USE ONLY. Never install on a production or long-lived public site.
 *              Restrict the VM firewall to your own IP while it is active.
 */

// Lets the benign workload post comments quickly without "you are posting too quickly" errors.
add_filter( 'comment_flood_filter', '__return_false' );

add_action( 'init', function () {
	if ( ! isset( $_GET['dbexp_id'] ) ) {
		return;
	}
	global $wpdb;
	$wpdb->hide_errors();

	// INTENTIONAL VULNERABILITY: unsanitised value concatenated into a numeric context.
	$rows = $wpdb->get_results(
		"SELECT ID, post_title FROM {$wpdb->posts} WHERE ID = " . $_GET['dbexp_id']
	);

	// Only a row count is echoed (never row data), so the lab endpoint cannot leak content.
	header( 'Content-Type: text/plain' );
	echo 'rows=' . count( (array) $rows );
	exit;
} );
