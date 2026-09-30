<?php
/**
 * Plugin Name: DBExp Query Logger (must-use)
 * Description: Logs every $wpdb query, with HTTP context, as one JSON line. Research use only.
 *
 * Why here and not the MariaDB general log? The general log has no idea which HTTP request,
 * WordPress user or URL a query belongs to. Hooking $wpdb's "query" filter gives us that context.
 *
 * Control switch: create the file /var/lib/dbexp/LOGGER_OFF to disable logging (for a
 * "no monitoring" control run). Remove it to enable again.
 */
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	return; // ignore setup / clean-up done from the command line
}
if ( ! defined( 'DBEXP_LOG' ) ) {
	define( 'DBEXP_LOG', '/var/log/dbexp/events.jsonl' );
}
if ( file_exists( '/var/lib/dbexp/LOGGER_OFF' ) ) {
	return;
}

$GLOBALS['dbexp_req'] = array(
	'id'  => bin2hex( random_bytes( 6 ) ), // groups all queries of one HTTP request
	'seq' => 0,
	'uid' => 0,
);

// Track the authenticated user (0 = anonymous) without triggering extra queries ourselves.
add_action( 'set_current_user', function () {
	global $current_user;
	$GLOBALS['dbexp_req']['uid'] = isset( $current_user->ID ) ? (int) $current_user->ID : 0;
}, 0 );

add_filter( 'query', function ( $sql ) {
	static $busy = false;
	if ( $busy ) {
		return $sql;
	}
	$busy = true;

	$r = &$GLOBALS['dbexp_req'];
	$r['seq']++;
	$event = array(
		'ts'      => microtime( true ),
		'req_id'  => $r['id'],
		'seq'     => $r['seq'],
		'user_id' => $r['uid'],
		'ip'      => isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '',
		'method'  => isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '',
		'uri'     => isset( $_SERVER['REQUEST_URI'] ) ? substr( $_SERVER['REQUEST_URI'], 0, 300 ) : '',
		// Ground-truth tag set by the workload generator. The detector never uses it for scoring.
		'label'   => isset( $_SERVER['HTTP_X_EXP_LABEL'] ) ? substr( $_SERVER['HTTP_X_EXP_LABEL'], 0, 64 ) : '',
		'sql'     => substr( $sql, 0, 20000 ),
	);
	@file_put_contents(
		DBEXP_LOG,
		json_encode( $event, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE ) . "\n",
		FILE_APPEND | LOCK_EX
	);

	$busy = false;
	return $sql;
}, 1 );
