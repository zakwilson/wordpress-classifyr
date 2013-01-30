<?php
/**
 * @package Classifyr
 */
/*
Plugin Name: Classifyr
Plugin URI: http://classifyr.com/?return=true
Description: Used by few, classifyr.com is meant to outperform Akismet. This Wordpress plugin is, however a fork of Akismet's. To get started: (note: private beta right now, you can't sign up this way yet) 1) Click the "Activate" link to the left of this description, 2) <s><a href="http://classifyr.com/get/?return=true">Sign up for an Classifyr API key</a></s>, and 3) Go to your <a href="admin.php?page=classifyr-key-config">Classifyr configuration</a> page, and save your API key.
Version: 0.0.1
Author: classifyr.com
Author URI: http://classifyr.com/wordpress/
License: GPLv2 or later
*/

/*
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

define('CLASSIFYR_VERSION', '0.0.1');
define('CLASSIFYR_PLUGIN_URL', plugin_dir_url( __FILE__ ));

/** If you hardcode a WP.com API key here, all key config screens will be hidden */
if ( defined('WPCOM_API_KEY') )
	$wpcom_api_key = constant('WPCOM_API_KEY');
else
	$wpcom_api_key = '';

// Make sure we don't expose any info if called directly
if ( !function_exists( 'add_action' ) ) {
	echo "Hi there!  I'm just a plugin, not much I can do when called directly.";
	exit;
}

if ( isset($wp_db_version) && $wp_db_version <= 9872 )
	include_once dirname( __FILE__ ) . '/legacy.php';

include_once dirname( __FILE__ ) . '/widget.php';

if ( is_admin() )
	require_once dirname( __FILE__ ) . '/admin.php';

function classifyr_init() {
	global $wpcom_api_key, $classifyr_api_host, $classifyr_api_port;
  $classifyr_api_host = 'classifyr.com';

	$classifyr_api_port = 80;
}
add_action('init', 'classifyr_init');

function classifyr_get_key() {
	global $wpcom_api_key;
	if ( !empty($wpcom_api_key) )
		return $wpcom_api_key;
	return get_option('wordpress_api_key');
}

function classifyr_check_key_status( $key, $ip = null ) {
	global $classifyr_api_host, $classifyr_api_port, $wpcom_api_key;
	$blog = urlencode( get_option('home') );
  $username = get_option('classifyr_username');
  $key = get_option('classifyr_api_key');
	$response = classifyr_http_post("key=$key&blog=$blog", 'rest.classifyr.com', '/1.1/verify-key', $classifyr_api_port, $ip);
	return $response;
}

// given a response from an API call like classifyr_check_key_status(), update the alert code options if an alert is present.
function classifyr_update_alert( $response ) {
	$code = $msg = null;
	if ( isset($response[0]['x-classifyr-alert-code']) ) {
		$code = $response[0]['x-classifyr-alert-code'];
		$msg = $response[0]['x-classifyr-alert-msg'];
	}
	
	// only call update_option() if the value has changed
	if ( $code != get_option( 'classifyr_alert_code' ) ) {
		update_option( 'classifyr_alert_code', $code );
		update_option( 'classifyr_alert_msg', $msg );
	}
}

function classifyr_verify_key( $key, $ip = null ) {
	/* $response = classifyr_check_key_status( $key, $ip ); */
	/* classifyr_update_alert( $response ); */
	/* if ( !is_array($response) || !isset($response[1]) || $response[1] != 'valid' && $response[1] != 'invalid' ) */
	/* 	return 'failed'; */
	/* return $response[0]; */
  return 'valid';
}

// if we're in debug or test modes, use a reduced service level so as not to polute training or stats data
function classifyr_test_mode() {
	if ( defined('CLASSIFYR_TEST_MODE') && CLASSIFYR_TEST_MODE )
		return true;
	return false;
}

// return a comma-separated list of role names for the given user
function classifyr_get_user_roles($user_id ) {
	$roles = false;
	
	if ( !class_exists('WP_User') )
		return false;
	
	if ( $user_id > 0 ) {
		$comment_user = new WP_User($user_id);
		if ( isset($comment_user->roles) )
			$roles = join(',', $comment_user->roles);
	}

	if ( is_multisite() && is_super_admin( $user_id ) ) {
		if ( empty( $roles ) ) {
			$roles = 'super_admin';
		} else {
			$comment_user->roles[] = 'super_admin';
			$roles = join( ',', $comment_user->roles );
		}
	}

	return $roles;
}

// Returns array with headers in $response[0] and body in $response[1]
function classifyr_http_post($request, $host, $path, $port = 80, $ip=null) {
	global $wp_version, $classifyr_api_host;

  $username = get_option('classifyr_username');
  $key = get_option('classifyr_api_key');

	$classifyr_ua = "WordPress/{$wp_version} | ";
	$classifyr_ua .= 'Classifyr/' . constant( 'CLASSIFYR_VERSION' );

	$classifyr_ua = apply_filters( 'classifyr_ua', $classifyr_ua );

	$content_length = strlen( $request );

  $checksum = sha1($request . $key);

	$http_host = $host;
	// use a specific IP if provided
	// needed by classifyr_check_server_connectivity()
	if ( $ip && long2ip( ip2long( $ip ) ) ) {
		$http_host = $ip;
	} else {
		$http_host = $host;
	}

  $http_host = "classifyr.com"; //FIXME - this host nonsense should go
	
	// use the WP HTTP class if it is available
	if ( function_exists( 'wp_remote_post' ) ) {
		$http_args = array(
                       'method' => 'POST',
                       'body'			=> $request,
                       'headers'		=> array(
                                             'Content-Type'	=> 'application/json',
                                             'Host'			=> $http_host,
                                             'User-Agent'	=> $classifyr_ua,
                                             'classifyr-api-checksum' => $checksum,
                                             'classifyr-api-user' => $username
                                             ),
                       'httpversion'	=> '1.0',
                       'timeout'		=> 15
		);

		$classifyr_url = "http://{$http_host}{$path}";
		$response = wp_remote_post( $classifyr_url, $http_args );
		if ( is_wp_error( $response ) )
      return '';

		return array( $response['headers'], $response['body'] );
	} else {
		$http_request  = "POST $path HTTP/1.0\r\n";
		$http_request .= "Host: $host\r\n";
		$http_request .= "Content-Type: application/json\r\n";
		$http_request .= "Content-Length: {$content_length}\r\n";
		$http_request .= "User-Agent: {$classifyr_ua}\r\n";
    $http_request .= "classifyr-api-user: $username";
    $http_request .= "classifyr-api-checksum: $checksum";
		$http_request .= "\r\n";
		$http_request .= $request;
		
		$response = '';
		if( false != ( $fs = @fsockopen( $http_host, $port, $errno, $errstr, 10 ) ) ) {
			fwrite( $fs, $http_request );

			while ( !feof( $fs ) )
				$response .= fgets( $fs, 1160 ); // One TCP-IP packet
			fclose( $fs );
			$response = explode( "\r\n\r\n", $response, 2 );
		}
		return $response;
	}
}

// filter handler used to return a spam result to pre_comment_approved
function classifyr_result_spam( $approved ) {
	// bump the counter here instead of when the filter is added to reduce the possibility of overcounting
	if ( $incr = apply_filters('classifyr_spam_count_incr', 1) )
		update_option( 'classifyr_spam_count', get_option('classifyr_spam_count') + $incr );
	// this is a one-shot deal
	remove_filter( 'pre_comment_approved', 'classifyr_result_spam' );
	return 'spam';
}

function classifyr_result_hold( $approved ) {
	// once only
	remove_filter( 'pre_comment_approved', 'classifyr_result_hold' );
	return '0';
}

// how many approved comments does this author have?
function classifyr_get_user_comments_approved( $user_id, $comment_author_email, $comment_author, $comment_author_url ) {
	global $wpdb;
	
	if ( !empty($user_id) )
		return $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $wpdb->comments WHERE user_id = %d AND comment_approved = 1", $user_id ) );
		
	if ( !empty($comment_author_email) )
		return $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $wpdb->comments WHERE comment_author_email = %s AND comment_author = %s AND comment_author_url = %s AND comment_approved = 1", $comment_author_email, $comment_author, $comment_author_url ) );
		
	return 0;
}

function classifyr_microtime() {
	$mtime = explode( ' ', microtime() );
	return $mtime[1] + $mtime[0];
}

// log an event for a given comment, storing it in comment_meta
function classifyr_update_comment_history( $comment_id, $message, $event=null ) {
	global $current_user;

	// failsafe for old WP versions
	if ( !function_exists('add_comment_meta') )
		return false;
	
	$user = '';
	if ( is_object($current_user) && isset($current_user->user_login) )
		$user = $current_user->user_login;

	$event = array(
		'time' => classifyr_microtime(),
		'message' => $message,
		'event' => $event,
		'user' => $user,
	);

	// $unique = false so as to allow multiple values per comment
	$r = add_comment_meta( $comment_id, 'classifyr_history', $event, false );
}

// get the full comment history for a given comment, as an array in reverse chronological order
function classifyr_get_comment_history( $comment_id ) {
	
	// failsafe for old WP versions
	if ( !function_exists('add_comment_meta') )
		return false;

	$history = get_comment_meta( $comment_id, 'classifyr_history', false );
	usort( $history, 'classifyr_cmp_time' );
	return $history;
}

function classifyr_cmp_time( $a, $b ) {
	return $a['time'] > $b['time'] ? -1 : 1;
}

// this fires on wp_insert_comment.  we can't update comment_meta when classifyr_auto_check_comment() runs
// because we don't know the comment ID at that point.
function classifyr_auto_check_update_meta( $id, $comment ) {
	global $classifyr_last_comment;

	// failsafe for old WP versions
	if ( !function_exists('add_comment_meta') )
		return false;

	// wp_insert_comment() might be called in other contexts, so make sure this is the same comment
	// as was checked by classifyr_auto_check_comment
	if ( is_object($comment) && !empty($classifyr_last_comment) && is_array($classifyr_last_comment) ) {
		if ( intval($classifyr_last_comment['comment_post_ID']) == intval($comment->comment_post_ID)
			&& $classifyr_last_comment['comment_author'] == $comment->comment_author
			&& $classifyr_last_comment['comment_author_email'] == $comment->comment_author_email ) {
				// normal result: true or false
				if ( $classifyr_last_comment['classifyr_result'] == 'true' ) {
					update_comment_meta( $comment->comment_ID, 'classifyr_result', 'true' );
					classifyr_update_comment_history( $comment->comment_ID, __('Classifyr caught this comment as spam'), 'check-spam' );
					if ( $comment->comment_approved != 'spam' )
						classifyr_update_comment_history( $comment->comment_ID, sprintf( __('Comment status was changed to %s'), $comment->comment_approved), 'status-changed'.$comment->comment_approved );
				} elseif ( $classifyr_last_comment['classifyr_result'] == 'false' ) {
					update_comment_meta( $comment->comment_ID, 'classifyr_result', 'false' );
					classifyr_update_comment_history( $comment->comment_ID, __('Classifyr cleared this comment'), 'check-ham' );
					if ( $comment->comment_approved == 'spam' ) {
						if ( wp_blacklist_check($comment->comment_author, $comment->comment_author_email, $comment->comment_author_url, $comment->comment_content, $comment->comment_author_IP, $comment->comment_agent) )
							classifyr_update_comment_history( $comment->comment_ID, __('Comment was caught by wp_blacklist_check'), 'wp-blacklisted' );
						else
							classifyr_update_comment_history( $comment->comment_ID, sprintf( __('Comment status was changed to %s'), $comment->comment_approved), 'status-changed-'.$comment->comment_approved );
					}
				// abnormal result: error
				} else {
					update_comment_meta( $comment->comment_ID, 'classifyr_error', time() );
					classifyr_update_comment_history( $comment->comment_ID, sprintf( __('Classifyr was unable to check this comment (response: %s), will automatically retry again later.'), substr($classifyr_last_comment['classifyr_result'], 0, 50)), 'check-error' );
				}
				
				// record the complete original data as submitted for checking
				if ( isset($classifyr_last_comment['comment_as_submitted']) )
					update_comment_meta( $comment->comment_ID, 'classifyr_as_submitted', $classifyr_last_comment['comment_as_submitted'] );
		}
	}
}

add_action( 'wp_insert_comment', 'classifyr_auto_check_update_meta', 10, 2 );

function classifyr_check_comment($comment){
  $req = json_encode(array('url' => $comment['comment_author_url'],
                           'message' => $comment['comment_author_IP'] . " " . $comment['comment_content']));
  $resp = classifyr_http_post($req, $classifyr_api_host, '/api/simple-spam/classify', $classifyr_api_port);
  return $resp;
}

function classifyr_learn_comment($comment, $cat){
  $req = json_encode(array('url' => $comment['comment_author_url'],
                           'message' => $comment['comment_author_IP'] . " " . $comment['comment_content'],
                           'category' => $cat));
  $resp = classifyr_http_post($req, $classifyr_api_host, '/api/simple-spam/learn', $classifyr_api_port);
  return $resp;
}

function classifyr_auto_check_comment( $commentdata ) {
	global $classifyr_api_host, $classifyr_api_port, $classifyr_last_comment;

	$comment = $commentdata;
	$comment['user_ip']    = $_SERVER['REMOTE_ADDR'];
	$comment['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
	$comment['referrer']   = $_SERVER['HTTP_REFERER'];
	$comment['blog']       = get_option('home');
	$comment['blog_lang']  = get_locale();
	$comment['blog_charset'] = get_option('blog_charset');
	$comment['permalink']  = get_permalink($comment['comment_post_ID']);
	
	if ( !empty( $comment['user_ID'] ) ) {
		$comment['user_role'] = classifyr_get_user_roles($comment['user_ID']);
	}

	$classifyr_nonce_option = apply_filters( 'classifyr_comment_nonce', get_option( 'classifyr_comment_nonce' ) );
	$comment['classifyr_comment_nonce'] = 'inactive';
	if ( $classifyr_nonce_option == 'true' || $classifyr_nonce_option == '' ) {
		$comment['classifyr_comment_nonce'] = 'failed';
		if ( isset( $_POST['classifyr_comment_nonce'] ) && wp_verify_nonce( $_POST['classifyr_comment_nonce'], 'classifyr_comment_nonce_' . $comment['comment_post_ID'] ) )
			$comment['classifyr_comment_nonce'] = 'passed';

		// comment reply in wp-admin
		if ( isset( $_POST['_ajax_nonce-replyto-comment'] ) && check_ajax_referer( 'replyto-comment', '_ajax_nonce-replyto-comment' ) )
			$comment['classifyr_comment_nonce'] = 'passed';

	}

	if ( classifyr_test_mode() )
		$comment['is_test'] = 'true';
		
	foreach ($_POST as $key => $value ) {
		if ( is_string($value) )
			$comment["POST_{$key}"] = $value;
	}

	$ignore = array( 'HTTP_COOKIE', 'HTTP_COOKIE2', 'PHP_AUTH_PW' );

	foreach ( $_SERVER as $key => $value ) {
		if ( !in_array( $key, $ignore ) && is_string($value) )
			$comment["$key"] = $value;
		else
			$comment["$key"] = '';
	}

	$post = get_post( $comment['comment_post_ID'] );
	$comment[ 'comment_post_modified_gmt' ] = $post->post_modified_gmt;
		
	$commentdata['comment_as_submitted'] = $comment;

	$response = classifyr_check_comment($comment);

	classifyr_update_alert( $response );
	$commentdata['classifyr_result'] = $response[1];
	if ( 'spam' == $response[1] ) {
		// classifyr_spam_count will be incremented later by classifyr_result_spam()
		add_filter('pre_comment_approved', 'classifyr_result_spam');

		do_action( 'classifyr_spam_caught' );

		$last_updated = strtotime( $post->post_modified_gmt );
		$diff = time() - $last_updated;
		$diff = $diff / 86400;
		
		if ( $post->post_type == 'post' && $diff > 30 && get_option( 'classifyr_discard_month' ) == 'true' && empty($comment['user_ID']) ) {
			// classifyr_result_spam() won't be called so bump the counter here
			if ( $incr = apply_filters('classifyr_spam_count_incr', 1) )
				update_option( 'classifyr_spam_count', get_option('classifyr_spam_count') + $incr );
			wp_safe_redirect( $_SERVER['HTTP_REFERER'] );
			die();
		}
	}
	
	// if the response is neither true nor false, hold the comment for moderation and schedule a recheck
	if ( 'spam' != $response[1] && 'ham' != $response[1] ) {
		if ( !current_user_can('moderate_comments') ) {
			add_filter('pre_comment_approved', 'classifyr_result_hold');
		}
		if ( !wp_next_scheduled( 'classifyr_schedule_cron_recheck' ) ) {
			wp_schedule_single_event( time() + 1200, 'classifyr_schedule_cron_recheck' );
		}
	}
	
	if ( function_exists('wp_next_scheduled') && function_exists('wp_schedule_event') ) {
		// WP 2.1+: delete old comments daily
		if ( !wp_next_scheduled('classifyr_scheduled_delete') )
			wp_schedule_event(time(), 'daily', 'classifyr_scheduled_delete');
	} elseif ( (mt_rand(1, 10) == 3) ) {
		// WP 2.0: run this one time in ten
		classifyr_delete_old();
	}
	$classifyr_last_comment = $commentdata;

	classifyr_fix_scheduled_recheck();
	return $commentdata;
}

add_action('preprocess_comment', 'classifyr_auto_check_comment', 1);

function classifyr_delete_old() {
	global $wpdb;
	$now_gmt = current_time('mysql', 1);
	$comment_ids = $wpdb->get_col("SELECT comment_id FROM $wpdb->comments WHERE DATE_SUB('$now_gmt', INTERVAL 15 DAY) > comment_date_gmt AND comment_approved = 'spam'");
	if ( empty( $comment_ids ) )
		return;
		
	$comma_comment_ids = implode( ', ', array_map('intval', $comment_ids) );

	do_action( 'delete_comment', $comment_ids );
	$wpdb->query("DELETE FROM $wpdb->comments WHERE comment_id IN ( $comma_comment_ids )");
	$wpdb->query("DELETE FROM $wpdb->commentmeta WHERE comment_id IN ( $comma_comment_ids )");
	clean_comment_cache( $comment_ids );
	$n = mt_rand(1, 5000);
	if ( apply_filters('classifyr_optimize_table', ($n == 11)) ) // lucky number
		$wpdb->query("OPTIMIZE TABLE $wpdb->comments");

}

function classifyr_delete_old_metadata() { 
	global $wpdb; 

	$now_gmt = current_time( 'mysql', 1 ); 
	$interval = apply_filters( 'classifyr_delete_commentmeta_interval', 15 );

	# enfore a minimum of 1 day
	$interval = absint( $interval );
	if ( $interval < 1 ) {
		return;
	}

	// classifyr_as_submitted meta values are large, so expire them 
	// after $interval days regardless of the comment status 
	while ( TRUE ) {
		$comment_ids = $wpdb->get_col( "SELECT $wpdb->comments.comment_id FROM $wpdb->commentmeta INNER JOIN $wpdb->comments USING(comment_id) WHERE meta_key = 'classifyr_as_submitted' AND DATE_SUB('$now_gmt', INTERVAL {$interval} DAY) > comment_date_gmt LIMIT 10000" ); 

		if ( empty( $comment_ids ) ) {
			return; 
		}

		foreach ( $comment_ids as $comment_id ) {
			delete_comment_meta( $comment_id, 'classifyr_as_submitted' );
		}
	}

	/*
	$n = mt_rand( 1, 5000 ); 
	if ( apply_filters( 'classifyr_optimize_table', ( $n == 11 ), 'commentmeta' ) ) { // lucky number 
		$wpdb->query( "OPTIMIZE TABLE $wpdb->commentmeta" ); 
	}
	*/
} 

add_action('classifyr_scheduled_delete', 'classifyr_delete_old');
add_action('classifyr_scheduled_delete', 'classifyr_delete_old_metadata'); 

function classifyr_check_db_comment( $id, $recheck_reason = 'recheck_queue' ) {
    global $wpdb, $classifyr_api_host, $classifyr_api_port;

    $id = (int) $id;
    $c = $wpdb->get_row( "SELECT * FROM $wpdb->comments WHERE comment_ID = '$id'", ARRAY_A );
    if ( !$c )
        return;

    $c['user_ip']    = $c['comment_author_IP'];
    $c['user_agent'] = $c['comment_agent'];
    $c['referrer']   = '';
    $c['blog']       = get_option('home');
    $c['blog_lang']  = get_locale();
    $c['blog_charset'] = get_option('blog_charset');
    $c['permalink']  = get_permalink($c['comment_post_ID']);
    $id = $c['comment_ID'];
	if ( classifyr_test_mode() )
		$c['is_test'] = 'true';
	$c['recheck_reason'] = $recheck_reason;

  $response = classifyr_check_comment($c);
  return $response[1];
}

function classifyr_cron_recheck() {
	global $wpdb;

	$status = classifyr_verify_key( classifyr_get_key() );
	if ( get_option( 'classifyr_alert_code' ) || $status == 'invalid' ) {
		// since there is currently a problem with the key, reschedule a check for 6 hours hence
		wp_schedule_single_event( time() + 21600, 'classifyr_schedule_cron_recheck' );
		return false;
	}
	
	delete_option('classifyr_available_servers');

	$comment_errors = $wpdb->get_col( "
		SELECT comment_id
		FROM {$wpdb->prefix}commentmeta
		WHERE meta_key = 'classifyr_error'
		LIMIT 100
	" );
	
	foreach ( (array) $comment_errors as $comment_id ) {
		// if the comment no longer exists, or is too old, remove the meta entry from the queue to avoid getting stuck
		$comment = get_comment( $comment_id );
		if ( !$comment || strtotime( $comment->comment_date_gmt ) < strtotime( "-15 days" ) ) {
			delete_comment_meta( $comment_id, 'classifyr_error' );
			continue;
		}
		
		add_comment_meta( $comment_id, 'classifyr_rechecking', true );
		$status = classifyr_check_db_comment( $comment_id, 'retry' );

		$msg = '';
		if ( $status == 'true' ) {
			$msg = __( 'Classifyr caught this comment as spam during an automatic retry.' );
		} elseif ( $status == 'false' ) {
			$msg = __( 'Classifyr cleared this comment during an automatic retry.' );
		}
		
		// If we got back a legit response then update the comment history
		// other wise just bail now and try again later.  No point in
		// re-trying all the comments once we hit one failure.
		if ( !empty( $msg ) ) {
			delete_comment_meta( $comment_id, 'classifyr_error' );
			classifyr_update_comment_history( $comment_id, $msg, 'cron-retry' );
			update_comment_meta( $comment_id, 'classifyr_result', $status );
			// make sure the comment status is still pending.  if it isn't, that means the user has already moved it elsewhere.
			$comment = get_comment( $comment_id );
			if ( $comment && 'unapproved' == wp_get_comment_status( $comment_id ) ) {
				if ( $status == 'true' ) {
					wp_spam_comment( $comment_id );
				} elseif ( $status == 'false' ) {
					// comment is good, but it's still in the pending queue.  depending on the moderation settings
					// we may need to change it to approved.
					if ( check_comment($comment->comment_author, $comment->comment_author_email, $comment->comment_author_url, $comment->comment_content, $comment->comment_author_IP, $comment->comment_agent, $comment->comment_type) )
						wp_set_comment_status( $comment_id, 1 );
				}
			}
		} else {
			delete_comment_meta( $comment_id, 'classifyr_rechecking' );
			wp_schedule_single_event( time() + 1200, 'classifyr_schedule_cron_recheck' );
			return;
		}
		delete_comment_meta( $comment_id, 'classifyr_rechecking' );
	}
	
	$remaining = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $wpdb->commentmeta WHERE meta_key = 'classifyr_error'" ) );
	if ( $remaining && !wp_next_scheduled('classifyr_schedule_cron_recheck') ) {
		wp_schedule_single_event( time() + 1200, 'classifyr_schedule_cron_recheck' );
	}
}
add_action( 'classifyr_schedule_cron_recheck', 'classifyr_cron_recheck' );

function classifyr_add_comment_nonce( $post_id ) {
	echo '<p style="display: none;">';
	wp_nonce_field( 'classifyr_comment_nonce_' . $post_id, 'classifyr_comment_nonce', FALSE );
	echo '</p>';
}

$classifyr_comment_nonce_option = apply_filters( 'classifyr_comment_nonce', get_option( 'classifyr_comment_nonce' ) );

if ( $classifyr_comment_nonce_option == 'true' || $classifyr_comment_nonce_option == '' )
	add_action( 'comment_form', 'classifyr_add_comment_nonce' );

global $wp_version;
if ( '3.0.5' == $wp_version ) { 
	remove_filter( 'comment_text', 'wp_kses_data' ); 
	if ( is_admin() ) 
		add_filter( 'comment_text', 'wp_kses_post' ); 
}

function classifyr_fix_scheduled_recheck() {
	$future_check = wp_next_scheduled( 'classifyr_schedule_cron_recheck' );
	if ( !$future_check ) {
		return;
	}

	if ( get_option( 'classifyr_alert_code' ) > 0 ) {
		return;
	}

	$check_range = time() + 1200;
	if ( $future_check > $check_range ) {
		wp_clear_scheduled_hook( 'classifyr_schedule_cron_recheck' );
		wp_schedule_single_event( time() + 300, 'classifyr_schedule_cron_recheck' );
	}
}
