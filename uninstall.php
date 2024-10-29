<?php
/**
 * Fired when the plugin is uninstalled.  
 */
 
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
} 
 

global $wpdb;
$tablename = $wpdb->prefix."criminalip"; 
$wpdb->query( "DROP TABLE IF EXISTS `$tablename`" );  