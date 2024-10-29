<?php  
/**
 * Plugin Name:         Anti-Brute Force, Login Fraud Detector 
 * Plugin URI:          https://criminalip.io/
 * Description:         Anti-Brute Force, Login Fraud Detector plugin is a security plugin that detects and blocks malicious IP addresses attempting to log into Wordpress sites with real-time intelligence data from Criminal IP. Hackers attempting brute-force attacks on WordPress sites do not use normal IP addresses.  Criminal IP is an IP address-based intelligence search engine platform that scans worldwide IP addresses daily and collects such malicious information. 
 * Version:             1.0.0
 * Requires at least:   5.7
 * Requires PHP:        5.6
 * Author:              Criminal IP
 * Author URI:          https://criminalip.io
 * License:             GPL v2 or later
 * License URI:         https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:         wp-criminalip 
 */

define('abflfd_tbl', 'criminalip');  
define('abflfd_host', 'https://api.criminalip.io');  
define('abflfd_hostpath_ip', '/v1/ip/data');  
define('abflfd_me', '/v1/user/me');   
define('abflfd_hostpath_status', '/v1/user/usage/status');  
define('abflfd_media_url_ko', 'gzfLAAzIVIM'); 
define('abflfd_media_url_ja', '433wR_edNek'); 
define('abflfd_media_url_en', 'fjm2uNnWjkM');   

$path = preg_replace('/wp-content.*$/', '', __DIR__);   
$class = new abflfd_detectorclass(__FILE__);
$class->init(); 

$is_tor = 0;
$is_vpn = 0; 
$is_proxy= 0; 
$is_hosting = 0; 
$is_mobile = 0;  
$is_darkweb= 0; 
$is_scanner = 0; 
$is_snort= 0; 
$time_limit = 0; 
$api_key =''; 
$whitelist_ip = ''; 

class abflfd_detectorclass {  
    public static function init() {
        register_activation_hook( __FILE__, array( 'abflfd_detectorclass', 'install' ) );
        add_action( 'plugins_loaded', 'abflfd_load_textdomain_fds');  
    }


    public static function install() {  
        global $wpdb; 
        $charset_collate = $wpdb->get_charset_collate();  
        $wpdb->query(" CREATE OR REPLACE TABLE {$wpdb->prefix}".abflfd_tbl." (
            c_id INT(11) NOT NULL AUTO_INCREMENT,
            c_type CHAR(1) NOT NULL, 
            c_data LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL , 
            c_useyn CHAR(1) NOT NULL DEFAULT 'Y',   
            c_date datetime NULL,
            PRIMARY KEY (c_id)
            ){$charset_collate}; ");    
    }
} 
abflfd_detectorclass::init(); 

class abflfd_config_info_login_detector
{
    public bool $_is_tor;
    public bool $_is_vpn;
    public bool $_is_proxy; 
    public bool $_is_hosting; 
    public int $_time_limit;    
    public ?string $_api_key;  
    public ?string $_whitelist_ip;   

    public function __construct(int $_is_tor, int $_is_vpn , int $_is_proxy, int $_is_hosting, 
    int $_time_limit, ?string $_api_key, ?string $_whitelist_ip)
    { 
        global $is_tor;
        global $is_vpn ;
        global $is_proxy; 
        global $is_hosting ; 
        global $time_limit ;
        global $api_key ; 
        global $whitelist_ip; 

        $is_tor = $_is_tor;
        $is_vpn = $_is_vpn;
        $is_proxy = $_is_proxy;
        $is_hosting = $_is_hosting; 
        $time_limit = $_time_limit;
        $api_key = $_api_key;    
        $whitelist_ip = $_whitelist_ip;     
    } 
} 
 
function abflfd_get_userip() {   
     
    $ip_address = filter_input(INPUT_SERVER, 'REMOTE_ADDR', FILTER_VALIDATE_IP);
    if ($ip_address === false) {
        $ip_address = '';
    } else if (filter_input(INPUT_SERVER, 'HTTP_CLIENT_IP', FILTER_VALIDATE_IP)) {
        $ip_address = filter_input(INPUT_SERVER, 'HTTP_CLIENT_IP', FILTER_VALIDATE_IP);
    } else if (filter_input(INPUT_SERVER, 'HTTP_X_FORWARDED_FOR', FILTER_VALIDATE_IP)) {
        $ip_address = filter_input(INPUT_SERVER, 'HTTP_X_FORWARDED_FOR', FILTER_VALIDATE_IP);
        $ip_address_s = explode(',', $ip_address);
        $ip_address = array_shift($ip_address_s);
    }  
    return filter_var($ip_address, FILTER_VALIDATE_IP) ?: '';
}


function abflfd_load_textdomain_fds() {  
    load_plugin_textdomain( 'wp-criminalip', false, dirname( plugin_basename( __FILE__ )) . '/languages/' ); 
} 

add_action( 'admin_enqueue_scripts', 'abflfd_login_detector_enqueue_scripts' ); 
function abflfd_login_detector_enqueue_scripts() { 
    wp_enqueue_script( 'chart-min-js', plugin_dir_url( __FILE__ ) . '/admin/js/chart.min.js', array( 'jquery' ) );
    wp_enqueue_script( 'chart-js', plugin_dir_url( __FILE__ ) . '/admin/js/chart.js', array( 'jquery' ) );
    wp_enqueue_script( 'chart-3-7-0-js', plugin_dir_url( __FILE__ ) . '/admin/js/chart_3_7_0.js', array( 'jquery' ) ); 
}
 
add_action ('wp_login','abflfd_plugin_login_detector');  
function abflfd_plugin_login_detector()
{         
    global $wpdb;   
    global $whitelist_ip;  

    $sql =  "SELECT c_data FROM {$wpdb->prefix}".abflfd_tbl." WHERE c_type = 'S' AND c_useyn = 'Y'  ORDER BY c_data DESC LIMIT 1"; 
    $returnValue = $wpdb->get_row($sql);  
    
    if($returnValue && $returnValue->c_data){  
        $data = json_decode($returnValue->c_data);   
        new abflfd_config_info_login_detector($data->is_tor,$data->is_vpn,$data->is_proxy,$data->is_hosting,$data->time_limit,$data->api_key,$data->whitelist_ip);    
        $ipaddress = abflfd_get_userip();    
         
        if (filter_var($ipaddress, FILTER_VALIDATE_IP) === false) {
            abflfd_ip_block();  
        }   
        
        abflfd_check_illegal_pattern_ip_login_detector();
         
        if(strpos($whitelist_ip , $ipaddress) !== false){ 
            return; 
        }
        else{    

            // If accessed from a blocked IP address, access will be restricted.
            if(abflfd_check_exists_blockip_login_detector()){    
                abflfd_ip_block();  
            }else{   
                // Through the Criminalio API, we check if the accessed IP corresponds to the IP set for login restriction options.
                if(abflfd_check_illegal_pattern_ip_login_detector()){     
                }
                else {  
                    abflfd_insert_accessinfo_login_detector("A",array('ip' => abflfd_get_userip()));   
                }
            } 
        } 
    }
    return ;  
} 

function  abflfd_ip_block(){   
  
    echo  '<div style="width:99%; height:100%; text-align:center;background-color: #f7f7f7;  margin:0px 0px 0px 0px ;position: absolute;top: 50%;    transform: translateY(-50%);">';
    echo  '<div style="display:inline-block;">';  
    echo  '<p style="padding:30px 0  0  0 ;"><img src="'. plugin_dir_url( __FILE__ ) .'/images/logout.png"></p>';
    echo  '<p style="font-weight:bold;font-size:40px;color:#e80000;padding:0px;"> '. __( 'Login has been blocked','wp-criminalip').'</p>';
    echo  '<p style="font-weight:bold">'. __( 'This site is equipped with the Criminal IP Anti-Brute Force, Login Fraud Detector plugin','wp-criminalip').'</p>';
    echo  '<p>'. __( 'This security plugin detects and blocks suspicious login attempts with malicious IP addresses','wp-criminalip').'</p>';
    echo  '<p>'. __( 'Please use this site with a normal IP address','wp-criminalip').'</p>';
    echo '<p>' . esc_html( __( 'If you are still blocked despite using a normal IP address, please contact', 'wp-criminalip' ) ) . ' <a href="mailto:' . esc_attr( sanitize_email( 'support@aispera.com' ) ) . '">support@aispera.com</a>.</p>';
    echo  '<p><a href="'.esc_url( 'https://www.criminalip.io').'" target="_blank"><img src="'. plugin_dir_url( __FILE__ ) .'/images/banner.png" style="width: 800px;"></a></p></div></div>'; 
    
    exit;  
}

function abflfd_check_exists_blockip_login_detector(){    
    global $time_limit ;   
    global $api_key ;   
    $blockyn = false;   
    if (isset($api_key) && $api_key <> ''){  
        global $wpdb;   
        $query = "SELECT * FROM {$wpdb->prefix}".abflfd_tbl." WHERE c_type = 'B' AND  c_useyn = 'Y' AND  json_value(c_data,'$.ip') ='". abflfd_get_userip()."' order by c_id desc limit 1 ";   
        
        $returnValue = $wpdb->get_row($query);   

        if($returnValue && $returnValue->c_useyn == "Y"){   
            $time_current = date("Y-m-d H:i:s");
            $time_finish = date("Y-m-d H:i:s", strtotime($returnValue->c_date." +".$time_limit." minutes"));   

            if(strtotime($time_current) < strtotime($time_finish)){ 
                $blockyn = true;  
            }   
        }  
    } 

    if($blockyn == false){ 
        $query = "UPDATE {$wpdb->prefix}".abflfd_tbl." SET c_useyn = 'N' WHERE  c_type = 'B' AND c_useYn = 'Y'  AND json_value(c_data,'$.ip') ='". abflfd_get_userip()."'" ; 
        $wpdb->query($wpdb->prepare($query));         
    }  
    return $blockyn;
} 
 
function abflfd_check_illegal_pattern_ip_login_detector(){   
 
    global $is_tor;
    global $is_vpn ;
    global $is_proxy; 
    global $is_hosting ; 
    global $time_limit ;
    global $api_key ;  
    $returnvalue = false;  
 
    if (isset($api_key) && $api_key <> ''){  
        $criminalip_info = abflfd_call_criminal_api_login_detector($api_key);    

        if($criminalip_info != null){  
 
            
            $ip = $criminalip_info->ip; 
            $ip_is_tor =  $criminalip_info->tags->is_tor;   
            $ip_is_vpn  =  $criminalip_info->tags->is_vpn;
            $ip_is_proxy =   $criminalip_info->tags->is_proxy;
            $ip_is_hosting  =   $criminalip_info->tags->is_hosting; 
            $ip_cn_info = $criminalip_info->whois->data[0]->org_country_code;   
            
            $reason_tor = false; 
            $reason_vpn = false; 
            $reason_proxy = false; 
            $reason_hosting  = false;  

            if($is_tor && $ip_is_tor) $reason_tor = true; 
            if($is_vpn && $ip_is_vpn) $reason_vpn = true; 
            if($is_proxy && $ip_is_proxy) $reason_proxy = true; 
            if($is_hosting && $ip_is_hosting) $reason_hosting = true;  

            if( $reason_tor || $reason_vpn || $reason_proxy || $reason_hosting){    
                $data = array("ip" => $ip ,  
                "ip_is_tor" => $ip_is_tor,
                "ip_is_vpn" => $ip_is_vpn,
                "ip_is_proxy" => $ip_is_proxy , 
                "ip_is_hosting" => $ip_is_hosting, 
                "ip_cn_info" => $ip_cn_info ,
                "reason" => array("reason_is_tor" => $reason_tor,
                                  "reason_is_vpn" => $reason_vpn,
                                  "reason_is_proxy" => $reason_proxy,
                                  "reason_is_hosting" => $reason_hosting));  
                abflfd_insert_accessinfo_login_detector("B",$data);  
                $returnvalue = true;
            } 
        }  
    }
    return $returnvalue; 
}    
 

function abflfd_call_criminal_api_login_detector($api_key){    

    $ip = abflfd_get_userip(); 
    $params = '?ip=' . $ip . '&full=true';  
    $headers = "x-api-key: ".$api_key."\r\n";   
    $args = array(
        'headers' =>  $headers 
    );    

    $url = abflfd_host.abflfd_hostpath_ip.$params; 
 
    try {    
            $result =  wp_remote_get( $url, $args );  
            if($result['response']['code'] == 200){  

                $response = json_decode($result['body']);    
                return $response; 
            }    
            else    
                return null;             
        }
    catch ( Exception $e ){
        return null;  
    } 
}
 
add_action( 'admin_menu', 'abflfd_login_detector_menu_setting');
function abflfd_login_detector_menu_setting()
{         
    $icon_url = plugin_dir_url( __FILE__ ) . '/images/abflfd_simbol.svg';   
    add_menu_page( 'Anti-Brute Force, Login Fraud Detector',   
    'Criminal IP', 'edit_posts', 'anti-brute-force-login-fraud-detector', 'abflfd_plugin_options_page', $icon_url); 
}
  
add_filter('abflfd_plugin_action_links_'.plugin_basename(__FILE__), 'abflfd_login_detector_action_links');
function abflfd_login_detector_action_links( $links ) {
    array_unshift($links, '<a href="' . admin_url( 'admin.php?page=anti-brute-force-login-fraud-detector' ) . '">' . __( 'Settings','index') . '</a>'); 
    return $links;
} 

add_action('admin_init','abflfd_plugin_register_settings' );    
function abflfd_plugin_register_settings() {   

    global $wpdb;  
    $sql = "SELECT c_data FROM {$wpdb->prefix}".abflfd_tbl." WHERE c_type = 'S' AND c_useyn = 'Y'  ORDER BY c_data DESC LIMIT 1";  
    $returnValue = $wpdb->get_row($sql);  
      
    if($returnValue && $returnValue->c_data){  
        $data = json_decode($returnValue->c_data);     
        new abflfd_config_info_login_detector($data->is_tor,$data->is_vpn,$data->is_proxy,$data->is_hosting,$data->time_limit,$data->api_key,$data->whitelist_ip);    
    } 

    global $is_tor;
    global $is_vpn ;
    global $is_proxy; 
    global $is_hosting ; 
    global $time_limit ;
    global $api_key ;    
    global $whitelist_ip; 
  
    register_setting('abflfd_options_group','abflfd_option_name', 'abflfd_save'); 
    add_settings_section('abflfd_settings_section','','abflfd_settings_section_callback' ,'abflfd_setting_page'); 
    add_settings_field(  
        'api_key',	 __('<span style="padding:10px"><a href='.esc_url('https://www.criminalip.io/mypage/information').' target=\'_blank\'><input type=\'button\' class=\'button button-primary\' value="'.__('Issue API Key','wp-criminalip').'"></a></span>','wp-criminalip'),
        'abflfd_settings_text_callback',	 
        'abflfd_setting_page',									 
        'abflfd_settings_section',					 
         array('abflfd_label' => 'api_key','default'=> $api_key,)													 
    );        
  
    add_settings_section('abflfd_block_ip_settings_section','','abflfd_block_ip_settings_section_callback','abflfd_setting_page');
    add_settings_field(
        'is_vpn',		
        __('<p style=\'padding-left:1px; margin:0px;\'>Login Limit Options</p>','wp-criminalip'),		
        'abflfd_settings_ip_callback',		
        'abflfd_setting_page',								 
        'abflfd_block_ip_settings_section',					
        array(
            'abflfd_label_vpn' => 'is_vpn',
            'abflfd_label_tor' => 'is_tor',
            'abflfd_label_proxy' => 'is_proxy', 
            'abflfd_label_hosting' => 'is_hosting', 
            'abflfd_txt_vpn' => __('Block VPN IP Addresses','wp-criminalip'),
            'abflfd_txt_tor' => __('Block Tor IP Addresses','wp-criminalip'),
            'abflfd_txt_proxy' => __('Block Proxy IP Addresses','wp-criminalip'),
            'abflfd_txt_hosting' => __('Block Hosting IP Addresses','wp-criminalip'),
            'abflfd_txt_vpn_default' => $is_vpn,
            'abflfd_txt_tor_default' => $is_tor,
            'abflfd_txt_proxy_default' => $is_proxy,
            'abflfd_txt_hosting_default' => $is_hosting,
        )			
    );  
    add_settings_field(
        'time_limit',		 
        __('&nbsp;','wp-criminalip'),				
        'abflfd_settings_time_callback',		
        'abflfd_setting_page',							
        'abflfd_block_ip_settings_section',	
        array(
            'abflfd_label' => 'time_limit', 
            'abflfd_element_description' => __( 'minutes after Can be re-logged','criminalip' ),
            'default' => $time_limit, 
        )												
    );      

    add_settings_section('abflfd_middle_settings_section','','abflfd_middle_section_callback','abflfd_setting_page');  
    add_settings_field( 
        'whitelist_ip',							
        __('<p style=\'padding:0 0 0 1px; margin-top:0px;\'>Whitelisted IP addresses</p> ', 'wp-criminalip' ),	 
        'abflfd_settings_whitelist_callback' ,	
        'abflfd_setting_page',							
        'abflfd_middle_settings_section',	
        array(
            'abflfd_label' => 'whitelist_ip',
            'description'   => $whitelist_ip,
            'rowcount' => '5',  
        )														
    );  
} 
 
function abflfd_save( $input ) {  

    global $wpdb;  
 
    $is_tor = 0 ;
    $is_vpn = 0 ;
    $is_proxy = 0 ; 
    $is_hosting = 0 ; 
    $time_limit = 0 ;
    $api_key = '';   
    $whitelist_ip = '';
   

    if ( isset( $input ) ) {    

        foreach ( $input as $key => $value ) {  
            
            if($key == 'is_tor') {$is_tor = $value; continue; }
            if($key == 'is_vpn') {$is_vpn = $value;  continue;}
            if($key == 'is_proxy') {$is_proxy = $value;   continue;} 
            if($key == 'is_hosting') {$is_hosting = $value; continue; }
            if($key == 'time_limit') {$time_limit = $value;  continue; }
            if($key == 'api_key'){$api_key = $value;   continue; }
            if($key == 'whitelist_ip'){$whitelist_ip = $value;   continue; }
        }  
 

        if ($whitelist_ip <> '' && !abflfd_validateIPAddress($whitelist_ip)) {
            $error_message =  __('The entered IP address is not valid', 'wp-criminalip' );  
            add_settings_error('abflfd_options_group', 'invalid_ip_address', $error_message, 'error');
            return false;
        }

        if(isset($api_key)){  
            $headers = "x-api-key: ".$api_key."\r\n"; 
            $args = array(  'headers' =>  $headers ); 
            $url = abflfd_host . abflfd_me ;  
            $result = wp_remote_post($url, $args);  
            $response = json_decode($result['body']);  

            if($response->status == 200)
            { 
                $update_row = array('c_useyn' => 'N');
                $wpdb->update($wpdb->prefix.abflfd_tbl,$update_row,array('c_type'=>'S','c_useyn'=>'Y')); 
                abflfd_insert_accessinfo_login_detector("S",array( "is_tor" => $is_tor,
                                                            "is_vpn" => $is_vpn,
                                                "is_proxy" => $is_proxy , 
                                                "is_hosting" => $is_hosting, 
                                                "time_limit" => $time_limit,
                                                "api_key"=> $api_key,
                                                "whitelist_ip"=> $whitelist_ip,
                                            ));   
            } 
            else{
                $error_message = __('Not a valid api key. Please check api key.', 'wp-criminalip');
                add_settings_error('abflfd_options_group', 'invalid_api_key', $error_message, 'error');
                return false;
            }
        }   
    } 
} 

function abflfd_validateIPAddress($ipAddress) { 
    $ipRegex = '/^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])$/';
    return preg_match($ipRegex, $ipAddress);
  }

function abflfd_insert_accessinfo_login_detector($c_type, $arr){ 
    global $wpdb;        
    $data = array('c_type'=> $c_type, 'c_data'=> json_encode($arr) , 'c_date' => date("Y-m-d H:i:s"));  
    $format = array('%s');   
    $wpdb->insert($wpdb->prefix.abflfd_tbl, $data, $format);  

}  
 
function abflfd_settings_section_callback() {  
    echo "<p style='padding:5px;'>" . __("This is a security plugin that detects and blocks automated login attacks with IP address monitoring.<br> Issue a free Criminal IP API key and activate the plugin.",'wp-criminalip') . "</p>" ;
    echo '<p>';
    echo '<div style="display:inline;border-top-left-radius:30px; border-top-right-radius:30px; border-bottom-left-radius:30px; border-bottom-right-radius:30px;">';   
    echo '<span style="float:left;width:510px; height:120px; padding: 20px;display: block;background-color: white;">';
    echo '<p><img src="'. plugin_dir_url( __FILE__ ) .'/images/logo.png"></p>';
    echo '<p>'.__('Thank you for using the Criminal IP Anti-Brute Force, Login Fraud Detector plugin','wp-criminalip').'</p>';
    echo '<p>'.__('This plugin detects and blocks malicious IP addresses attempting to login to the user\'s Wordpress site.','wp-criminalip').'</p>';
    echo '<p>'.__('Criminal IP is an intelligence search engine platform that collects malicious information from worldwide IP addresses and domains','wp-criminalip').'</p>';
    echo '<p>'.__('Check out what you can do more with Criminal IP','wp-criminalip').'</p>';
    echo '<p><a href="'.esc_url( 'https://www.criminalip.io').'" target=\'_blank\'><input type=\'button\' class=\'button button-primary\' value=\'Go to Criminal IP\'></a></p></span>';
    echo '<span style="padding: 10px;display: block;background-color: white;border-top-left-radius:30px; border-top-right-radius:30px; border-bottom-left-radius:30px; border-bottom-right-radius:30px;width:1070px;">';

    $locale = apply_filters( 'plugin_locale', determine_locale(), 'wp-criminalip' ); 
    if ($locale == 'ko_KR'){
        echo "<iframe width='521' height='293' src='".esc_url( 'https://www.youtube.com/embed/'.abflfd_media_url_ko )."' frameborder='0' allow='accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share' allowfullscreen></iframe>";
    }elseif($locale == 'ja'){
        echo "<iframe width='521' height='293' src='".esc_url( 'https://www.youtube.com/embed/'.abflfd_media_url_ja )."' frameborder='0' allow='accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share' allowfullscreen></iframe>";
    }else{
        echo "<iframe width='521' height='293' src='".esc_url( 'https://www.youtube.com/embed/'.abflfd_media_url_en )."' frameborder='0' allow='accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share' allowfullscreen></iframe>";
    } 
    
    echo '</span></div><p>';
    echo '<div style="display:inline; ">';   
    echo '<span style="float:left;width:1070px; height:90px;padding-left: 20px; display: block;background-color: white;">'; 
    echo '<p style="margin:1px;padding: 10px 0 0 0;" >'.__('Upgrade your Criminal IP plan to detect more attacks','wp-criminalip').'</p>'; 
    echo '<p style="padding:0px 0 10 10;display: block;"><a href="'.__(esc_url( 'https://www.criminalip.io/en/pricing'),'wp-criminalip').'" target="_blank"><input type="button" class="button button-primary" value="&nbsp;Upgrade Plan&nbsp;"></a></p></span>';
    echo "</div>";   
    echo '<div style="display:inline;padding:0px;">';   
    echo '<span style="float:left;width:1100px;height:90px;padding-left: 20px; padding-bottom 0px;display: block;">'; 
    echo '<p style="font-size:19px;font-weight:bold;margin:20px 0px 0px 0px;">'.__('Criminal IP API Key','wp-criminalip').'</p> '; 
    echo '<p style="margin:1px;padding: 5px 0 0 0;">'.__('Create a Criminal IP account, log in','wp-criminalip').'</p> '; 
    echo '<p style="margin:1px;padding: 5px 0 0 0;"> '.__('And create an API key in My Page by clicking the Issue API Key button.','wp-criminalip').'</p>'; 
    echo '</span>'; 
    echo '<span style="padding-left: 10px;display: block; width:1100px;">'; 
}  

function abflfd_block_ip_settings_section_callback() { 
    echo '<span style="float:left;width:1100px;padding-left: 10px; height: 90px;padding-bottom 0px;display: block; ">';
    echo '<p style="font-size:19px;font-weight:bold;margin:10px 0px 0px 0px;">'.__('Prevent Brute-force Attack Option','wp-criminalip'); 
    echo '<p style="margin:1px;padding: 5px 0 0 0;">'.__('Hackers attempting brute-force attacks use VPN, Proxy, Tor, Hosting IP, etc. to prevent tracking.','wp-criminalip'); 
    echo '<p style="margin:1px;padding: 5px 0 0 0;">'.__('Set restrictive IP address options and login wait time. We recommend you enable all options to prevent as many attacks as possible.','wp-criminalip'); 
    echo '</span>'; 
    return;
}
  

function abflfd_middle_section_callback() {
    echo '<span style="float:left;width:1100px;padding-left: 1px; height: 90px;padding-bottom 0px;display: block; ">';
    echo '<p style="font-size:19px;font-weight:bold;margin:0px 0px 0px 0px;">'.__('Whitelist','wp-criminalip'); 
    echo '<p style="margin:1px;padding: 5px 0 0 0;">'.__('Whitelisted IP addresses are not subject to Criminal IP login blocking.','wp-criminalip'); 
    echo '<p style="margin:1px;padding: 5px 0 0 0;">'.__('We recommend you register only trusted IP addresses such as office IP addresses.','wp-criminalip'); 
    echo '</span>'; 
    return;
}
      

function abflfd_settings_text_callback( $args ) {

    $field_id = isset($args['abflfd_label']) ? $args['abflfd_label'] : null;
    $field_default = isset($args['default']) ? $args['default'] : null;   
    $options = get_option( 'abflfd_option_name' );
    $option = $field_default; 
    if ( ! empty( $options[ $field_id ] ) ) 
        $option = $options[ $field_id ]; 
    ?>	  
        <input type="text" name="<?php echo 'abflfd_option_name[' . esc_html($field_id) . ']'; ?>" id="<?php echo 'abflfd_option_name[' . esc_html($field_id) . ']'; ?>" value="<?php echo  $option; ?>" style="width: 99%;" /> 
    <?php 
}

function abflfd_settings_time_callback( $args ) {

    $field_id = isset($args['abflfd_label']) ? $args['abflfd_label'] : null;
    $field_default = isset($args['default']) ? $args['default'] : null; 
    $abflfd_element_description = isset($args['abflfd_element_description']) ? $args['abflfd_element_description'] : null;  
    $options = get_option( 'abflfd_option_name' );
    $option = $field_default;

    if ( ! empty( $options[ $field_id ] ) ) 
        $option = $options[ $field_id ]; 
    ?> 
        <input type="number" step="1" min="1" name="<?php echo 'abflfd_option_name[' . esc_html($field_id) . ']'; ?>" id="<?php echo 'abflfd_option_name[' . esc_html($field_id) . ']'; ?>" value="<?php echo esc_attr( $option ); ?>" style="width: 100px;" />
        <span><?php if (!empty($abflfd_element_description)) echo esc_html($abflfd_element_description); ?> </span> 
    <?php 
}
  


function abflfd_settings_ip_callback( $args ) {

    $fld_vpn = isset($args['abflfd_label_vpn']) ? $args['abflfd_label_vpn'] : null;
    $fld_tor = isset($args['abflfd_label_tor']) ? $args['abflfd_label_tor'] : null;
    $fld_proxy = isset($args['abflfd_label_proxy']) ? $args['abflfd_label_proxy'] : null;
    $fld_hosting = isset($args['abflfd_label_hosting']) ? $args['abflfd_label_hosting'] : null; 

    $field_abflfd_txt_vpn_default = isset($args['abflfd_txt_vpn_default']) ? $args['abflfd_txt_vpn_default'] : null;
    $field_abflfd_txt_tor_default = isset($args['abflfd_txt_tor_default']) ? $args['abflfd_txt_tor_default'] : null;
    $field_abflfd_txt_proxy_default = isset($args['abflfd_txt_proxy_default']) ? $args['abflfd_txt_proxy_default'] : null;
    $field_abflfd_txt_hosting_default = isset($args['abflfd_txt_hosting_default']) ? $args['abflfd_txt_hosting_default'] : null;
    
    $abflfd_txt_vpn = isset($args['abflfd_txt_vpn']) ? $args['abflfd_txt_vpn'] : null;;
    $abflfd_txt_tor = isset($args['abflfd_txt_tor']) ? $args['abflfd_txt_tor'] : null;;
    $abflfd_txt_proxy = isset($args['abflfd_txt_proxy']) ? $args['abflfd_txt_proxy'] : null;;
    $abflfd_txt_hosting = isset($args['abflfd_txt_hosting']) ? $args['abflfd_txt_hosting'] : null;;
     
    $options = get_option( 'abflfd_option_name' );
    $option_vpn = $field_abflfd_txt_vpn_default;
    $option_tor = $field_abflfd_txt_tor_default;
    $option_proxy = $field_abflfd_txt_proxy_default;
    $option_hosting = $field_abflfd_txt_hosting_default;

    if ( ! empty( $options[ $fld_vpn ] ) ) 
        $option_vpn = $options[ $fld_vpn];
    

    if ( ! empty( $options[ $fld_tor ] ) ) 
        $option_tor = $options[ $fld_tor];
    

    if ( ! empty( $options[ $fld_proxy ] ) ) 
        $option_proxy = $options[ $fld_proxy];

    if ( ! empty( $options[ $fld_hosting ] ) ) 
        $option_hosting = $options[ $fld_hosting];   

    ?>	 
        <p>  
            <label for="<?php echo 'abflfd_option_name[' . esc_html($fld_vpn) . ']'; ?>">
                <input type="checkbox" name="<?php echo 'abflfd_option_name[' . esc_html($fld_vpn) . ']'; ?>" 
                id="<?php echo 'abflfd_option_name[' . $fld_vpn . ']'; ?>"
                <?php checked( $option_vpn, true, 1 ); ?> value="1" /><span style="padding-left: 10px;"><?php if (!empty($abflfd_txt_vpn)) echo esc_html($abflfd_txt_vpn); ?><span>
            </label>
        </p><p>
            <label for="<?php echo 'abflfd_option_name[' . esc_html($fld_tor) . ']'; ?>">
                <input type="checkbox" name="<?php echo 'abflfd_option_name[' . esc_html($fld_tor) . ']'; ?>" 
                id="<?php echo 'abflfd_option_name[' . $fld_tor . ']'; ?>" 
                <?php checked( $option_tor, true, 1 ); ?> value="1" /><span style="padding-left: 10px;"><?php if (!empty($abflfd_txt_tor)) echo esc_html($abflfd_txt_tor); ?><span>
            </label>
        </p><p>   
            <label for="<?php echo 'abflfd_option_name[' . esc_html($fld_proxy) . ']'; ?>">
                <input type="checkbox" name="<?php echo 'abflfd_option_name[' . esc_html($fld_proxy) . ']'; ?>" 
                id="<?php echo 'abflfd_option_name[' . $fld_proxy . ']'; ?>" 
                <?php checked( $option_proxy, true, 1 ); ?> value="1" /><span style="padding-left: 10px;"><?php if (!empty($abflfd_txt_proxy)) echo esc_html($abflfd_txt_proxy); ?><span>
            </label>
        </p><p>   
            <label for="<?php echo 'abflfd_option_name[' . esc_html($fld_hosting) . ']'; ?>">
                <input type="checkbox" name="<?php echo 'abflfd_option_name[' . esc_html($fld_hosting) . ']'; ?>"
                id="<?php echo 'abflfd_option_name[' . $fld_hosting . ']'; ?>" 
                <?php checked( $option_hosting, true, 1 ); ?> value="1" /><span style="padding-left: 10px;"><?php if (!empty($abflfd_txt_hosting)) echo esc_html($abflfd_txt_hosting); ?><span>
            </label>        
        </p>
    <?php 
}
 

function abflfd_settings_whitelist_callback( $args ) { 
    $fld_whitelist = isset($args['abflfd_label']) ? $args['abflfd_label'] : null;
    $fld_description = isset($args['description']) ? $args['description'] : null;
    $rows = isset($args['rowcount']) ? $args['rowcount'] : null;  
    $options = get_option( 'abflfd_option_name' );
    $option = $fld_description;

    if ( ! empty( $options[ $fld_whitelist ] ) ) 
        $option = $options[ $fld_whitelist ]; 

    if (empty($rows))
        $rows = 4; 
    ?>		
    <?php if (!empty($before_text)) echo esc_html($before_text) . '<br/>'; ?>
    <textarea type="text" rows="<?php echo esc_html($rows); ?>" cols="50" name="<?php echo 'abflfd_option_name[' . esc_html($fld_whitelist) . ']'; ?>" id="<?php echo 'abflfd_option_name[' . esc_html($fld_whitelist) . ']'; ?>"  style="width:99%" /><?php echo esc_attr( $option ); ?></textarea> 
    <?php

}  

function abflfd_plugin_options_page()
{
?>  

<div id="wrap">	
	<div class="wrap">  
	<?php
		$default_tab = 'api_key';
		if (isset($_GET['active_tab']))
			$active_tab = sanitize_text_field($_GET['active_tab']);
		else
			$active_tab = $default_tab; 
		settings_errors();
    ?>  
    <span style="font-size: 35px;font-weight:bold; padding:10px;border: 1px;line-height:normal;color:#2451a3" >
    <img src="<?php echo plugin_dir_url( __FILE__ ) . '/images/icon.png'; ?>" style="width: 40px; height: auto; margin-bottom: 0;"> Anti-Brute Force, Login Fraud Detector </span>
    <h2 class="nav-tab-wrapper"  sytle="border-bottom:: 1px solid #c3c4c7;"> 
        <a href="?page=anti-brute-force-login-fraud-detector&active_tab=api_key" class="nav-tab <?php echo $active_tab == 'api_key' ? 'nav-tab-active' : ''; ?>"><?php _e('General','wp-criminalip'); ?> </a>
        <?php 
        global $api_key;  
        if (isset($api_key) && $api_key <> ''){ ?>
		<a href="?page=anti-brute-force-login-fraud-detector&active_tab=list" class="nav-tab <?php echo $active_tab == 'list' ? 'nav-tab-active' : ''; ?>"><?php _e('Detected IP address','wp-criminalip'); ?> </a>   
        <a href="?page=anti-brute-force-login-fraud-detector&active_tab=graph" class="nav-tab <?php echo $active_tab == 'graph' ? 'nav-tab-active' : ''; ?>"><?php _e('Statistics','wp-criminalip'); ?> </a>     
        <?php } ?> 
    </h2>   
		<?php 
		if( $active_tab == 'api_key' ) { ?> 
       
			<form method="post" action="options.php">
			<input type="hidden" name="active_tab" value="<?php echo esc_attr($active_tab) ?>">
			<?php 
			settings_fields( 'abflfd_options_group' );
			do_settings_sections( 'abflfd_setting_page' );
			submit_button();
		} 

        if( $active_tab == 'blockpage' ) { ?>  
			<input type="hidden" name="active_tab" value="<?php echo esc_attr($active_tab) ?>">
			<?php 
            abflfd_ip_block();  
		} 

		if( $active_tab == 'list' ) {  
            echo "<p style='padding:5px;'>" . __("This is a list of IP addresses that were detected according to the restriction options.You can view the country information, detected content, and date of each IP address.",'wp-criminalip') . "</p>" ;
            $action = isset($_GET["action"]) ? sanitize_text_field(trim($_GET["action"])) : "";
  
            if($action=="detect-delete"){
                $c_id = isset($_GET["post_id"]) ? sanitize_text_field(intval($_GET["post_id"])) : ""; 
                global $wpdb; 
                $where = array('c_id' => intval(sanitize_text_field($c_id))); 
                $wpdb->delete( $wpdb->prefix.abflfd_tbl, $where); 
            }   
 
            $action = isset( $_POST['action'] ) ? sanitize_text_field( wp_unslash( $_POST['action'] ) ) : '';
            if($action=="bulk-delete"){ 
                if(!empty($_POST['bulk-delete'])){  
                    $delete_ids = array_map( 'sanitize_text_field', isset( $_POST['bulk-delete'] ) ? $_POST['bulk-delete'] : array() );
                     
                    if( !empty($delete_ids) ){
                        foreach ( $delete_ids as $id ) { 
                         
                            global $wpdb; 
                            $where = array('c_id' => intval(sanitize_text_field($id)));  
                            $wpdb->delete( $wpdb->prefix.abflfd_tbl, $where); 
                        }
                    } 
                } 
            }   

            ob_start();      
            include_once plugin_dir_path( __FILE__ ).'admin/partials/wp-list-table.php';   
            $template = ob_get_contents(); 
            ob_end_clean();   
            echo wp_kses( $template, 
                                    array(
                                        'option' => array(
                                            'value' => true
                                        ),
                                        'div' => array( 
                                            'class' => true ,
                                            'style' => true 
                                        ),
                                        'select' => array(
                                            'name' => true,
                                            'id' => true ,
                                        ),                
                                        'label' => array(
                                            'class' => true,
                                            'for' => true ,
                                        ),
                                        'input' => array(
                                            'type' => true,
                                            'id' => true ,
                                            'name' => true,
                                            'value' => true ,
                                            'class' => true ,
                                            'size'=> true ,
                                            'aria-describedby'=> true 
                                        ),                
                                        'form' => array(
                                            'method' => true,
                                            'name' => true,
                                            'action' => true 
                                        ),
                                        'p' => array(
                                            'class' => true ,
                                            'style' => true

                                        ),
                                        'thead' => array(),
                                        'table' => array(
                                            'class' => true 
                                        ),
                                        'a' => array(
                                            'class' => true ,
                                            'href' => true  
                                        ),
                                        'br'=> array(
                                            'class'=> true 
                                        ),
                                            'b'=> array(),
                                            'td'=> array(
                                            'id' => true ,
                                            'class' => true ,
                                            'data-colname'  => true ,
                                            'colspan' =>true 
                                        ),
                                        'tr'=> array(                 
                                            'scope' => true , 
                                            'id' => true ,
                                            'class' => true ,
                                            'style' => true
                                        ),
                                        'th'=> array(
                                            'scope' => true ,
                                            'id' => true ,
                                            'class' => true ,
                                            'style' => true ,
                                            'colspan' =>true 
                                        ), 
                                        'strong' => array(),
                                        'span'   => array(
                                            'class' => true ,
                                            'aria-hidden' => true 
                                        ),
                                    )
            );
		}      

		if( $active_tab == 'graph' ) {    

            global $api_key ;   
            global $wpdb; 

            if (isset($api_key) && $api_key <> ''){  

                $action = isset($_GET["action"]) ? sanitize_text_field(trim($_GET["action"])) : "" ; 
                echo "<div style='display:block'>";
                echo "<p style='font-weight:bold;padding: 5px;'>".__('Login Limit Statistics','wp-criminalip')."</p>";  
                echo "<p style='padding: 5px;'>".__('This is a graph comparing the number of blocked suspicious login attempts and the total number of login attempts.','wp-criminalip');  
      
                $search = "month"; 
                if($active_tab == 'graph'){
                    if (isset($_GET['search'])){
                        $search = sanitize_text_field($_GET['search']); 
                    } 
                }

                if($search == "month"){ 
                    $seven = date("Ym", strtotime("-6 month" , time())); $seven_month =  date("F" , strtotime("-6 month" , time()));   $seven_A = 0 ;  $seven_B = 0 ; 
                    $six   = date("Ym", strtotime("-5 month" , time())); $six_month   =  date("F" , strtotime("-5 month" , time()));   $six_A = 0   ;  $six_B = 0 ; 
                    $five  = date("Ym", strtotime("-4 month" , time())); $five_month  =  date("F" , strtotime("-4 month" , time()));   $five_A = 0  ;  $five_B = 0 ; 
                    $four  = date("Ym", strtotime("-3 month" , time())); $four_month  =  date("F" , strtotime("-3 month" , time()));   $four_A = 0  ;  $four_B = 0 ; 
                    $three = date("Ym", strtotime("-2 month" , time())); $three_month =  date("F" , strtotime("-2 month" , time()));   $three_A = 0 ;  $three_B = 0 ; 
                    $two   = date("Ym", strtotime("-1 month" , time())); $two_month   =  date("F" , strtotime("-1 month" , time()));   $two_A = 0   ;  $two_B = 0 ; 
                    $one   = date("Ym"); $one_month = date("F");   $one_A = 0 ;  $one_B = 0; 
 
                    $query = "
                                SELECT  
                                        c_type  as type 
                                        , count(c_type) as cnt  
                                        , DATE_FORMAT(c_date, '%Y%m') as dd 
                                        , DATE_FORMAT(c_date, '%M')  as  month
                                FROM {$wpdb->prefix}".abflfd_tbl." 
                                group by c_type , DATE_FORMAT(c_date, '%Y%m') 
                                having c_type <> 'S'
                            ";   
                }
                elseif($search == 'day'){

                    $seven = date("Ymd", strtotime("-6 day" , time())); $seven_month =  date("d" , strtotime("-6 day" , time()));   $seven_A = 0 ;  $seven_B = 0 ; 
                    $six   = date("Ymd", strtotime("-5 day" , time())); $six_month   =  date("d" , strtotime("-5 day" , time()));   $six_A = 0   ;  $six_B = 0 ; 
                    $five  = date("Ymd", strtotime("-4 day" , time())); $five_month  =  date("d" , strtotime("-4 day" , time()));   $five_A = 0  ;  $five_B = 0 ; 
                    $four  = date("Ymd", strtotime("-3 day" , time())); $four_month  =  date("d" , strtotime("-3 day" , time()));   $four_A = 0  ;  $four_B = 0 ; 
                    $three = date("Ymd", strtotime("-2 day" , time())); $three_month =  date("d" , strtotime("-2 day" , time()));   $three_A = 0 ;  $three_B = 0 ; 
                    $two   = date("Ymd", strtotime("-1 day" , time())); $two_month   =  date("d" , strtotime("-1 day" , time()));   $two_A = 0   ;  $two_B = 0 ; 
                    $one   = date("Ymd", strtotime("0 day" , time())); $one_month   =  date("d" , strtotime("-1 day" , time()));   $one_A = 0   ;  $one_B = 0 ; 
      
                    $query = "
                                SELECT  
                                    c_type  as type 
                                    , count(c_type) as cnt  
                                    , DATE_FORMAT(c_date, '%Y%m%d') as dd 
                                    , DATE_FORMAT(c_date, '%d')  as  month
                                FROM {$wpdb->prefix}".abflfd_tbl." 
                                group by c_type , DATE_FORMAT(c_date, '%Y%m%d') 
                                having c_type <> 'S'
                            ";    
                }
                elseif($search == 'week'){

                    $seven = date("Ymd", strtotime("-6 week" , time())); $seven_month =  date("Ymd" , strtotime("-6 week" , time()));   $seven_A = 0 ;  $seven_B = 0 ; 
                    $six   = date("Ymd", strtotime("-5 week" , time())); $six_month   =  date("Ymd" , strtotime("-5 week" , time()));   $six_A = 0   ;  $six_B = 0 ; 
                    $five  = date("Ymd", strtotime("-4 week" , time())); $five_month  =  date("Ymd" , strtotime("-4 week" , time()));   $five_A = 0  ;  $five_B = 0 ; 
                    $four  = date("Ymd", strtotime("-3 week" , time())); $four_month  =  date("Ymd" , strtotime("-3 week" , time()));   $four_A = 0  ;  $four_B = 0 ; 
                    $three = date("Ymd", strtotime("-2 week" , time())); $three_month =  date("Ymd" , strtotime("-2 week" , time()));   $three_A = 0 ;  $three_B = 0 ; 
                    $two   = date("Ymd", strtotime("-1 week" , time())); $two_month   =  date("Ymd" , strtotime("-1 week" , time()));   $two_A = 0   ;  $two_B = 0 ; 
                    $one   = date("Ymd", strtotime("0 week" , time())); $one_month   =  date("Ymd" , strtotime("0 week" , time()));   $one_A = 0   ;  $one_B = 0 ;   
                    
                    $seven = date('oW',mktime(0, 0, 0, date("m", strtotime("-6 week" , time())), date("d", strtotime("-6 week" , time())), date("Y", strtotime("-6 week" , time())))); 
                    $six = date('oW',mktime(0, 0, 0, date("m", strtotime("-5 week" , time())), date("d", strtotime("-5 week" , time())), date("Y", strtotime("-5 week" , time())))); 
                    $five = date('oW',mktime(0, 0, 0, date("m", strtotime("-4 week" , time())), date("d", strtotime("-4 week" , time())), date("Y", strtotime("-4 week" , time())))); 
                    $four = date('oW',mktime(0, 0, 0, date("m", strtotime("-3 week" , time())), date("d", strtotime("-3 week" , time())), date("Y", strtotime("-3 week" , time())))); 
                    $three = date('oW',mktime(0, 0, 0, date("m", strtotime("-2 week" , time())), date("d", strtotime("-2 week" , time())), date("Y", strtotime("-2 week" , time())))); 
                    $two = date('oW',mktime(0, 0, 0, date("m", strtotime("-1 week" , time())), date("d", strtotime("-1 week" , time())), date("Y", strtotime("-1 week" , time())))); 
                    $one = date('oW',mktime(0, 0, 0, date("m", strtotime("0 week" , time())), date("d", strtotime("0 week" , time())), date("Y", strtotime("0 week" , time())))); 
                      
                    $query ="     
                                SELECT  
                                    c_type  as type 
                                    , count(c_type) as cnt  
                                    , YEARWEEK(c_date) dd 
                                    , DATE_FORMAT(c_date, '%Y%m%d')    as month
                                FROM {$wpdb->prefix}".abflfd_tbl." 
                                group by c_type,YEARWEEK(c_date)   
                                having c_type <> 'S'
                            ";   
                }
                elseif($search == 'year'){

                    $seven = date("Y", strtotime("-6 year" , time())); $seven_month =  date("Y" , strtotime("-6 year" , time()));   $seven_A = 0 ;  $seven_B = 0 ; 
                    $six   = date("Y", strtotime("-5 year" , time())); $six_month   =  date("Y" , strtotime("-5 year" , time()));   $six_A = 0   ;  $six_B = 0 ; 
                    $five  = date("Y", strtotime("-4 year" , time())); $five_month  =  date("Y" , strtotime("-4 year" , time()));   $five_A = 0  ;  $five_B = 0 ; 
                    $four  = date("Y", strtotime("-3 year" , time())); $four_month  =  date("Y" , strtotime("-3 year" , time()));   $four_A = 0  ;  $four_B = 0 ; 
                    $three = date("Y", strtotime("-2 year" , time())); $three_month =  date("Y" , strtotime("-2 year" , time()));   $three_A = 0 ;  $three_B = 0 ; 
                    $two   = date("Y", strtotime("-1 year" , time())); $two_month   =  date("Y" , strtotime("-1 year" , time()));   $two_A = 0   ;  $two_B = 0 ; 
                    $one   = date("Y", strtotime("0 year" , time())); $one_month   =  date("Y" , strtotime("0 year" , time()));   $one_A = 0   ;  $one_B = 0 ;  
     
                    $query = "
                                SELECT  
                                    c_type  as type  
                                    , count(c_type) as cnt    
                                    , year(c_date) as dd 
                                    , year(c_date) as  month
                                FROM {$wpdb->prefix}".abflfd_tbl."  
                                group by c_type , DATE_FORMAT(c_date, '%Y') 
                                having c_type <> 'S'
                            ";      
                }                   
                $returnValue = $wpdb->get_results($query);    
                foreach($returnValue as $row){
                    if($row->dd == $seven){ if($row->type == 'A'){  $seven_A = $row->cnt ;  } elseif($row->type == 'B'){ $seven_B = $row->cnt ;  }  $seven_month = $row->month ;  } 
                    elseif($row->dd == $six){ if($row->type == 'A'){  $six_A = $row->cnt ;  } elseif($row->type == 'B'){ $six_B = $row->cnt ;  }  $six_month = $row->month ;  } 
                    elseif($row->dd == $five){ if($row->type == 'A'){  $five_A = $row->cnt ;  } elseif($row->type == 'B'){ $five_B = $row->cnt ;  }  $five_month = $row->month ;  } 
                    elseif($row->dd == $four){ if($row->type == 'A'){  $four_A = $row->cnt ;  } elseif($row->type == 'B'){ $four_B = $row->cnt ;  }  $four_month = $row->month ;  } 
                    elseif($row->dd == $three){ if($row->type == 'A'){  $three_A = $row->cnt ;  } elseif($row->type == 'B'){ $three_B = $row->cnt ;  }  $three_month = $row->month ;  } 
                    elseif($row->dd == $two){ if($row->type == 'A'){  $two_A = $row->cnt ;  } elseif($row->type == 'B'){ $two_B = $row->cnt ;  }  $two_month = $row->month ;  } 
                    elseif($row->dd == $one){ if($row->type == 'A'){  $one_A = $row->cnt ;  } elseif($row->type == 'B'){ $one_B = $row->cnt ;  }  $one_month = $row->month ;  } 
                } 
    
                printf('<div style="display:inline;">');
                printf('<span style="float:left;width:550px; padding: 10px;display: block;"><canvas id="mychart1"  width="500"  ></canvas></span>');
                printf('<a href="?page=anti-brute-force-login-fraud-detector&active_tab=graph&search=day"><input type=\'button\' value=\''.__('Day','wp-criminalip').'\' class=\'button button-primary\' style=\'margin-right:2px;width:70px\'></a>');
                printf('<a href="?page=anti-brute-force-login-fraud-detector&active_tab=graph&search=week"><input type=\'button\' value=\''.__('Week','wp-criminalip').'\' class=\'button button-primary\' style=\'margin-right:2px;width:70px\'></a>');
                printf('<a href="?page=anti-brute-force-login-fraud-detector&active_tab=graph&search=month"><input type=\'button\' value=\''.__('Month','wp-criminalip').'\' class=\'button button-primary\' style=\'margin-right:2px;width:70px\'></a>');
                printf('<a href="?page=anti-brute-force-login-fraud-detector&active_tab=graph&search=year"><input type=\'button\' value=\''.__('Year','wp-criminalip').'\' class=\'button button-primary\' style=\'margin-right:2px;width:70px\'></a>');
                printf('</div>');  
               
                printf('<script type="text/javascript">');
                printf('jQuery(document).ready(function($) {'); 
                printf(' var ctx = document.getElementById(\'mychart1\').getContext(\'2d\');');
                printf('		var chart = new Chart(ctx, {'); 
                printf('			type: \'bar\',   ');
                printf('			data: { ');
                printf('				labels: [\''.$seven_month.'\',\''.$six_month.'\',\''.$five_month.'\',\''.$four_month.'\',\''.$three_month.'\',\''.$two_month.'\',\''.$one_month.'\'],');
                printf('			  datasets: [');
                printf('							{');
                printf('							  label: \'login\',');
                printf('							  data: ['.$seven_A.', '.$six_A.', '.$five_A.', '.$four_A.', '.$three_A.', '.$two_A.', '.$one_A.'],');
                printf('							  borderColor:\'rgb(54, 162, 235)\',');
                printf('							  backgroundColor: \'rgb(54, 162, 235)\',');
                printf('							},');
                printf('							{');
                printf('							  label: \'Criminal\',');
                printf('							  data: ['.$seven_B.', '.$six_B.', '.$five_B.', '.$four_B.', '.$three_B.', '.$two_B.', '.$one_B.'],'); 
                printf('							  borderColor:  \'rgb(255, 99, 132)\',');
                printf('							  backgroundColor: \'rgb(255, 99, 132)\',');                
                printf('							}');
                printf('						  ]');
                printf('						},');
                printf('				options: {');
                printf('					responsive: false,');
                printf('					plugins: {');
                printf('					  title: {');
                printf('						display: false,');
                printf('						text: \'Suggested Min and Max Settings\'');
                printf('					  }');
                printf('					},');
                printf('					scales: {');
                printf('					  y: { ');
                printf('						suggestedMin: 30, ');
                printf('						suggestedMax: 50,');
                printf('					  }');
                printf('					}');
                printf('				  },	');		
                printf('			  });');
                printf('	}); ');
                printf('</script>  ');         
            
                printf('<div style="margin:260px 0px 0px 0px ;">');
                printf("<p style='font-weight:bold;padding: 5px;'>".__('Criminal IP API Usage Statistics','wp-criminalip')."</p>");  
                printf("<p style='padding:0 0 0 5px;'>".__('This is a graph showing the used number of API credits with the linked Criminal IP account. Credits are reset on the first day of each month.','wp-criminalip')."</p>"); 
                printf("<p style='font-size:12px;padding: 0 0 0 5px;'>".__("You can check Criminal IP Pricing page for credit criteria. To use more credits, a Plan Upgrade is required",'wp-criminalip')."(<a href='".esc_url( 'https://www.criminalip.io/'.__("en",'wp-criminalip').'/pricing')."' target='_black'>".esc_url( 'https://www.criminalip.io/'.__("en",'wp-criminalip').'/pricing')."</a>)</p>");        
                printf('</div>');     
            
                if (isset($api_key) && $api_key <> ''){  
                
                    $headers = "x-api-key: ".$api_key."\r\n"; 
                    $args = array('headers' =>  $headers);  
                    $url = abflfd_host . abflfd_hostpath_status ;    
                    $result = wp_remote_get($url, $args);  
                    $response = json_decode($result['body']);       

                    if($response->status == 200){    
 
                        $data = $response->data;   
                        $search_limit =  $data->asset_lookup_credit_limit; 
                        $search_left = $data->asset_lookup_credit_left; 
                        $search_used = $data->asset_lookup_usage;   
  

                        $query = "SELECT  'A',  MONth(c_date) MONTH ,  Date_Format(c_date , '%Y-%m') as MON, count(*) as Value  From  {$wpdb->prefix}".abflfd_tbl." where   c_type = 'A'     group by MON  union all   select 'B' ,MONth(c_date) MONTH ,  Date_Format(c_date , '%Y-%m') as MON, count(*) as Value From  {$wpdb->prefix}".abflfd_tbl." where   c_type = 'B' group by MON ";  
                        $returnValue = $wpdb->get_results($query);     
                        printf('<div style="display:inline;">');
                        printf('<span style="float:left; padding: 10px;display: block;"><canvas id="myChart0"  width="220" ></canvas></span>'); 
                        printf('</div>'); 

                        printf('<script>');
                        printf('const ctx = document.getElementById(\'myChart0\'); ');
                        printf('new Chart(ctx, {');
                        printf('type: \'doughnut\','); 
                        printf('data: {'); 
                        printf('labels: [\''.__('left  ','wp-criminalip').''.$search_left.' \', \''.__('used  ','wp-criminalip').''.$search_used.'\'],'); 
                        printf(' datasets: [{');
                        printf('label: \'# of datas\',');
                        printf('data: [');
                        printf($search_left);
                        printf(',');
                        printf($search_used);
                        print('],');
                        printf('backgroundColor: [\'rgb(255, 99, 132)\',\'rgb(54, 162, 235)\'],');                        
                        printf('borderWidth: 1,'); 
                        printf(' }]');
                        printf('	},');
                        printf('	options: { responsive: false,scales: { yAxes: [{ ticks: { display: false } }] } }');
                        printf('});');
                        printf('</script>');   
                    }    
                    else{
                        printf('<div style="display:inline;">');
                        printf('<span style="float:left; padding: 5px;display: block;"><p style="color:#ed5552">'.__('Not a valid api key. Please check api key.','wp-criminalip').'</p></span>'); 
                        printf('</div>');   
                    }
                } 
            }    
            ?>
        </form>
        </div>
    </div> 
    <?php
    }
}?>