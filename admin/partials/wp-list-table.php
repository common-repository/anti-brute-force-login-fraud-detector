<?php
	if ( ! class_exists( 'WP_List_Table' ) ) {
		require_once( ABSPATH . 'wp-admin/includes/screen.php' );
	} 
	define('PER_PAGE',10);


	class DetectTableList extends WP_List_Table{   
		 
		public function prepare_items()
		{  
			
			$this->process_bulk_action();

			$orderby = isset($_GET['orderby'])? sanitize_sql_orderby(trim($_GET['orderby'])): "";
			$order = isset($_GET['order'])? sanitize_sql_orderby(trim($_GET['order'])): "";
			$search_term = isset($_POST['s'])? sanitize_text_field(trim($_POST['s'])): ""; 

			$per_page = PER_PAGE ;
			$current_page = $this->get_pagenum(); 
			$total_items = self::record_count($search_term);
			
			$this->set_pagination_args(array(
				"total_items" => $total_items,
				"per_page" => $per_page  
			)); 

			$this->items = $this->wp_list_table_data($orderby, $order,$search_term, $per_page, $current_page );
 
			$columns = $this->get_columns();
			$hidden = $this->get_hidden_columns();
			$sortable = $this->get_sortable_columns();

			$this->_column_headers = array($columns,$hidden, $sortable); 
		}

		public static function record_count($search_term='') {
			global $wpdb; 
			$query = "SELECT COUNT(*) FROM  {$wpdb->prefix}".abflfd_tbl." WHERE c_type = 'B' ";   
			if(!empty($search_term)){
				$query .= " AND JSON_VALUE(c_data,'$.ip') LIKE '%".$search_term."%'";  
			}	
	
			$data =  $wpdb->get_var( $query ); 
			return $data; 
		}
		

		public function wp_list_table_data($orderby='', $order='' ,$search_term ='',$per_page= PER_PAGE, $page_number=1 ){ 
			global $wpdb;    

			$query ="	SELECT 
							 c_id
							,c_type
							,c_useyn
							,c_date  
							,JSON_VALUE(c_data,'$.ip') AS ip
							,JSON_VALUE(c_data,'$.ip_cn_info') AS cn  
							,JSON_VALUE(c_data,'$.ip_is_tor')  AS set_tor
							,JSON_VALUE(c_data,'$.ip_is_vpn')  AS set_vpn
							,JSON_VALUE(c_data,'$.ip_is_proxy') AS  set_proxy 
							,JSON_VALUE(c_data,'$.ip_is_hosting')  AS  set_hosting  
							,JSON_VALUE(JSON_EXTRACT(c_data, '$.reason'),'$.reason_is_tor') AS ip_tor
							,JSON_VALUE(JSON_EXTRACT(c_data, '$.reason'),'$.reason_is_vpn') AS ip_vpn
							,JSON_VALUE(JSON_EXTRACT(c_data, '$.reason'),'$.reason_is_proxy') AS ip_proxy
							,JSON_VALUE(JSON_EXTRACT(c_data, '$.reason'),'$.reason_is_hosting')  AS ip_hosting 
						FROM {$wpdb->prefix}".abflfd_tbl."   
						WHERE c_type  =  'B' ";  

			if(!empty($search_term)){
				$query .= " AND JSON_VALUE(c_data,'$.ip') LIKE '%".$search_term."%'";  
			}	

			if ( ! empty( $orderby ) ) {
				$query .= ' ORDER BY ' . esc_sql($orderby);
				$query .= ! empty( $order) ? ' ' . esc_sql( $order) : ' DESC';
			} else { 
				$query .= " ORDER BY c_id DESC";
			} 

			$query .= " LIMIT $per_page";
			$query .= ' OFFSET ' . ( $page_number - 1 ) * $per_page; 

			$data = $wpdb->get_results($query);    
			return $data;  
		}

		public function get_hidden_columns()
		{ 
			return array('set_tor','set_vpn','set_proxy','set_hosting'); 
		} 

		public function get_sortable_columns()
		{
			return array('c_id' => array('c_id', true ),
			'ip' => array('ip', true),
			'cn' => array('cn',true),
			'ip_tor' => array('ip_tor',true),
			'ip_vpn' => array('ip_vpn',true), 
			'ip_proxy' => array('ip_proxy', true), 
			'ip_hosting' => array('ip_hosting', true), 
			'c_date' => array('c_date', true), 
			);
		}
	 		
		public function get_bulk_actions(){
			$actions = array( 
				"bulk-delete" =>"Delete"
			);
			return $actions;
		}  

		public function get_columns()
		{
			$columns = array(
					"cb" =>"<input type='checkbox' />",
					"c_id"=>"no", 
					"ip"=>"ip", 
					"cn"=>"cn",
					"set_tor"=>"set_tor",
					"set_vpn"=>"set_vpn" ,
					"set_proxy"=>"set_proxy", 
					"set_hosting"=>"set_hosting",
					"ip_tor"=>"tor",
					"ip_vpn"=>"vpn" ,					
					"ip_proxy" =>"proxy"	,
					"ip_hosting"=>"hosting", 
					"c_date"=>"date" 	,
					"action"=>"action"														
			);  
			return $columns; 
		} 

		public function column_cb($item){
			return sprintf('<input type="checkbox" name="bulk-delete[]" value="%s"/>', $item->c_id);
		}
 
		public function column_default( $item, $column_name )
		{    
			switch($column_name){
				case "c_id":   
					return $item->c_id;  
				case "ip": 
					return $item->ip; 					
				case "cn": 
					return $item->cn; 	
				case "set_tor": 
					return getvalue($item->set_tor); 	
				case "set_vpn": 
					return getvalue($item->set_vpn); 	
				case "set_proxy":    
					return getvalue($item->set_proxy); 	
				case "set_hosting":  
					return getvalue($item->set_hosting);	
				case "ip_vpn":   
					return getvalue($item->ip_vpn); 	
				case "ip_tor":  
					return getvalue($item->ip_tor);	
				case "ip_proxy": 
					return getvalue($item->ip_proxy);	
				case "ip_hosting":  	
					return getvalue($item->ip_hosting);	 
				case "c_date": 
					return $item->c_date; 	
				case "action": 
					return '<a href="' . esc_url( add_query_arg( array( 'page' => $_GET['page'], 'active_tab' => 'list', 'action' => 'detect-delete', 'post_id' => esc_attr($item->c_id)), admin_url( 'admin.php' ) )) . '">Delete</a>';
				default : 
					return "no value";  
				} 
		} 
	} 

	function owt_show_data_list_table(){ 
		
		$owt_table = new DetectTableList();  
		echo "<form method='post' name='frm_search_post' action='" . esc_url( add_query_arg( array( 'page' => $_GET['page'], 'active_tab' => 'list' ), admin_url( 'admin.php' ) ) ) . "'>";
		$owt_table->prepare_items();
		echo "<div style='align:right'>"; 
		$owt_table->search_box("Search IP","search_post_id");
		echo "</div>" ;  
		$owt_table->display(); 
		echo "</form>";  
	}

	owt_show_data_list_table();

	function getvalue($data){
		if($data == 1)
			return "O"; 
		else 
			return "X"; 
	}