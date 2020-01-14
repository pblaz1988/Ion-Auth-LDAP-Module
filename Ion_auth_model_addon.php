public function login($identity, $password, $remember=FALSE)
	{
		$debug = false;
		$this->trigger_events('pre_login');

		if (empty($identity) || empty($password))
		{
			$this->set_error('login_unsuccessful');
			return FALSE;
		}

		$this->trigger_events('extra_where');
		
		$getDataFromLDAP = $this->login_ldap_helper($identity,$password);

		if ($debug) error_log(print_R($getDataFromLDAP,true),0);

		if (!empty($getDataFromLDAP))
		{
			// user exists in ldap directory but hasn't logged in yet
			// goto dirty hack
			
			narediQuery:
			$doesExist = $this->db->select($this->identity_column . ', email, id, password, active, last_login')
						  ->where($this->identity_column, $identity)
						  ->limit(1)
						  ->order_by('id', 'desc')
						  ->get($this->tables['users']);

			if ($doesExist->num_rows() < 1)
			{
				# user data is missing. push new data to db
				$additional_data = array(
				'first_name' => 'empty',
				'last_name' => 'empty',
				'company' => 'empty',
				'phone' => 'empty',
				);

				$registracija = $this->register($getDataFromLDAP['samaccountname'][0], $password, $getDataFromLDAP['samaccountname'][0], $additional_data);
				
				# goto dirty hack
				goto narediQuery;
			} elseif ($doesExist->num_rows() > 1) 
			{
				# something went very wrong .... during past logins
				if ($debug) error_log("ION_AUTH LDAP Helper - User account is duplicated! Check ion_auth table with users!");
				# do nothing
			}
			
			$user = $doesExist->row();
			$this->set_session($user);
			
			if ($remember && $this->config->item('remember_users', 'ion_auth'))
				{
					$this->remember_user($user->id);
				}
			
			$this->update_last_login($user->id);

			$this->clear_login_attempts($identity);

			
            
			// Regenerate the session (for security purpose: to avoid session fixation)
			$this->_regenerate_session();

			$this->trigger_events(array('post_login', 'post_login_successful'));
			$this->set_message('login_successful');

			return TRUE;
			
			
		}
		else
		{
			// throw back to base url if can't retrieve data from LDAP
			$this->set_error('login_unsuccessful');
			redirect(base_url());
			// die(0);
		}

		// Hash something anyway, just to take up time
		$this->hash_password($password);

		$this->increase_login_attempts($identity);

		$this->trigger_events('post_login_unsuccessful');
		$this->set_error('login_unsuccessful');

		return FALSE;
	}
	
	# LDAP Helper
	
	function login_ldap_helper($uname, $pwd)
	{
		$debug = false;
		
		$baseDN 			= $this->config->item('ldap_baseDN', 'ion_auth');
		$baseDNForBind 		= $this->config->item('ldap_baseDNForBind', 'ion_auth');
		$ldapZahtevanaGrupa = $this->config->item('ldap_ldapZahtevanaGrupa', 'ion_auth');
		$ldapRDN			= $this->config->item('ldap_bindUser', 'ion_auth');
		$ldapPass			= $this->config->item('ldap_pwd', 'ion_auth');
		$ldapSrv			= $this->config->item('ldap_server', 'ion_auth');

		try
		{
			$ldapConn = ldap_connect($ldapSrv) or die ("Failure");
			
			// ldap nastavitve
			ldap_set_option($ldapConn,LDAP_OPT_REFERRALS,0);
			ldap_set_option($ldapConn,LDAP_OPT_PROTOCOL_VERSION,3);
			
			
			# Bind to ldap server
			if ($ldapConn) {
				$ldapBindAdmin = ldap_bind($ldapConn,$ldapRDN,$ldapPass);
				# On admin login success
				if ($ldapBindAdmin) {
					# get DN from sAMAccountName
					$filter = '(sAMAccountName='.$uname.')';
					$attributes = array("name", "telephonenumber", "mail", "samaccountname","groups","memberof", "distinguishedname");
					$result = ldap_search($ldapConn, $baseDN, $filter, $attributes);
					
					
					$entries = ldap_get_entries($ldapConn, $result);

					# DN is available, try to bind
					$ldapBindUser = ldap_bind($ldapConn,$uname.$baseDNForBind,$pwd);

					if ($ldapBindUser)
					{
						# user bound
						# get group membership after bind process
						if (in_array($ldapZahtevanaGrupa, $entries[0]['memberof']))
							return $entries[0];
					}
				}
			}
			return array();	
		}
		catch (Exception $e)
		{
			if ($debug) error_log(pprint($e,true));
			return array();
		}
	}