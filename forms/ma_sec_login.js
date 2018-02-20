/**
 * @type {Number}
 *
 * @properties={typeid:35,uuid:"10EE9B6A-FD3E-473E-A267-494D9A43CE0A",variableType:8}
 */
var vGroup = -1;

/**
 * @properties={typeid:24,uuid:"22322C0F-9548-4E56-8750-7B3086C29B7E"}
 */
function onLoad(event)
{
	_super.onLoad(event);
	
	if(globals.svy_sec_l_startArg)
	{
		var args = globals.svy_sec_l_startArg.split("|");

		vUsername = args[0];
		globals.is_cas_authenticated = true;
	}
	
	if(globals.is_cas_authenticated)
	{
		elements.fld_userName.enabled = false;
		elements.fld_userName.bgcolor = '#d3d3d3';
		
		elements.fld_passWord.enabled = false;
		elements.fld_passWord.bgcolor = '#d3d3d3';
	}
	
	//hide group fields
	elements.lbl_group.visible = false;
	elements.fld_group.visible = false;
		
}

/**
 * @properties={typeid:24,uuid:"8E04001A-0F2F-4BD2-964D-8AEF6A0E6D18"}
 */
function onActionBntLogin(event)
{
	var params = {
        processFunction: process_login,
        message: '', 
        opacity: 0.5,
        paneColor: '#434343',
        textColor: '#EC1C24',
        showCancelButton: false,
        cancelButtonText: '',
        dialogName : '',
        fontType: 'Arial,4,25',
        processArgs: [event]
    };
	plugins.busy.block(params);
}

/**
 * @properties={typeid:24,uuid:"3C6BB990-15E1-4B51-B252-62187380A942"}
 */
function process_login()
{
	if(globals.is_cas_authenticated)
		loginWithCAS();
	else
		login();
	
	plugins.busy.unblock();
}

/**
 * Handle changed data.
 *
 * @param oldValue old value
 * @param newValue new value
 * @param {JSEvent} [event] the event that triggered the action
 *
 * @returns {Boolean}
 *
 * @private
 *
 * @properties={typeid:24,uuid:"3D22CC21-920F-4C99-9B88-7C81ECE7365D"}
 * @AllowToRunInFind
 */
function setGroupValueList(oldValue, newValue, event) 
{
	if(!globals.ma_utl_hasModule(globals.Module.AUTORIZZAZIONI))
		return true;
	var realValues = new Array();
	var displayValues = new Array();
	
	if (!globals.ma_utl_isNullOrUndefined(newValue)) 
	{
//		var sqlQuery = "SELECT \
//							grp.group_id, grp.name \
//						FROM \
//							sec_user_in_group sug \
//							INNER JOIN sec_user_org suo \
//								ON suo.user_org_id = sug.user_org_id \
//							INNER JOIN sec_group grp \
//								ON grp.group_id = sug.group_id \
//							LEFT OUTER JOIN sec_system_group ssg \
//								ON ssg.group_id = grp.group_id \
//						WHERE \
//							suo.organization_id = ? \
//							AND \
//							suo.user_id = ? \
//							AND \
//							ssg.locked IS NULL \
//						ORDER BY \
//							grp.name";
//		
//		var dsUserGroup = databaseManager.getDataSetByQuery(globals.nav_db_framework, sqlQuery, [vOrganization, vUser_id], -1);
		var dsUserGroup = globals.ma_sec_getUserGroups(vOrganization, vUser_id);
		if (dsUserGroup && dsUserGroup.getMaxRowIndex() > 0)
		{
			realValues[0] = -1;
			displayValues[0] = '';
			
			realValues = realValues.concat(dsUserGroup.getColumnAsArray(1));
			displayValues = displayValues.concat(dsUserGroup.getColumnAsArray(2));
			
			elements.error.text = '';
			vGroup = -1;
		}
		else
		{
			elements.error.text = i18n.getI18NMessage('ma.sec.lbl.no_group_for_user');
			vGroup = null;
		}
	}
	
	application.setValueListItems('vls_ma_sec_groups', displayValues, realValues);
//	vGroup = realValues[0];
	
	return true;
}

/**
 *	Method to let the user login, required is the group 'users' this method works with the sec_ tables
 *
 * @author Daniele Maccari

 * @properties={typeid:24,uuid:"256695B5-92A2-4176-838B-A954211B879F"}
 */
function login()
{
	//check if we should check the hash
	var _validated = security.authenticate('svy_sec_authenticate', 'svy_sec_validateHash',[{owner:vOwner, framework_db:vFramework_db}])

	if (!_validated) 
	{
		plugins.dialogs.showWarningDialog("Can't login","Somebody messed with the security data. Logging in is not possible. Please contact the administrator.","OK");
		
		if (application.isInDeveloper())
		{
			security.authenticate('svy_sec_authenticate', 'svy_sec_recalculateHash', [{owner:vOwner, framework_db:vFramework_db}]);
			plugins.dialogs.showWarningDialog("", "Developer: Hash recalculated, login again.", "OK");
		}
		return;
	}
	
	//check if user name and password are entered
	if((!vUsername) || (!vPassword) || (!vOwner))
	{
		elements.error.text = i18n.getI18NMessage('svy.fr.dlg.username_password_entered')
		return
	}
	
	if(vOrganization && !vGroup)
	{
		elements.error.text = i18n.getI18NMessage('ma.aut.msg.group_not_entered');
		return;
	}
	else
		elements.error.text = '';
	
	if (!vFirstLoginAttempt) {
		vFirstLoginAttempt = new Date();
	}	
	
	//user is already choosing organization
	if(vUser_id && vOrganization)
	{	
		//login the organization
		loginWithOrganization();
		return;
	}	

	// Call authentication module/method, authentication is done on server not on the client.
	var _authObj = new Object()
	_authObj.username = vUsername
	_authObj.password = vPassword
	_authObj.owner = vOwner
	_authObj.firstLoginAttempt = vFirstLoginAttempt
	_authObj.lastLoginAttempt = vLastLoginAttempt
	_authObj.framework_db = vFramework_db
	
	/** @type {{owner_id:String,user_id:String,error:String, success:Boolean}} */
	var _return = security.authenticate('svy_sec_authenticate', 'svy_sec_checkUserPassword',[_authObj])
	if(_return.success)
	{
		// set user id
		globals.svy_sec_lgn_user_id = _return.user_id
		
		// set owner id
		globals.svy_sec_lgn_owner_id = _return.owner_id
		
		// check whether the owner can access this solution
		if (!isOwnerEnabled())
		{
			globals.ma_utl_logError('i18n:ma.psl.err.auth.user_not_enabled', LOGGINGLEVEL.FATAL);
			showMessage(i18n.getI18NMessage('ma.psl.err.auth.user_not_enabled'));
			
			return;
		}

		// get organizations, if there are multiple organizations for this user he has to choose his organization
		/** @type {JSDataSet} */
		var _dat_org =  security.authenticate('svy_sec_authenticate', 'svy_sec_getOrganizations', [_return.user_id, _return.owner_id, vFramework_db])

		// set organization valuelist
		vUser_id = _return.user_id
		if(_dat_org.getMaxRowIndex() == 1)
		{
			vOrganization = _dat_org.getValue(1,2);
			setGroupValueList(null, vOrganization);
			loginWithOrganization();
		    return;
		}
		else
		{
			application.setValueListItems('svy_sec_lgn_organizations',_dat_org,true)
			elements.lbl_organization.visible = true
			elements.fld_organization.visible = true
		}
		
		/**
		 * Retrieve the stored organization only if it's the same owner
		 */
		if(vOwner === application.getUserProperty(application.getSolutionName() +'.ownername'))
		{
			// enter the organization id
			if(application.getUserProperty(application.getSolutionName() +'.organization')
				&& _dat_org.getColumnAsArray(2).indexOf(application.getUserProperty(application.getSolutionName() +'.organization') > -1))
				vOrganization = application.getUserProperty(application.getSolutionName() +'.organization')
		
		}
		else
			elements.fld_organization.requestFocus()

		// MA_Variazione : tolta selezione del gruppo di appartenenza in ingresso
		if(globals.ma_utl_hasModule(globals.Module.AUTORIZZAZIONI))
		{
//			elements.lbl_group.visible = true
//			elements.fld_group.visible = true
			
			if(vOrganization)
			{
				setGroupValueList(null, vOrganization);
//				if(application.getUserProperty(application.getSolutionName() +'.group'))
//					vGroup = application.getUserProperty(application.getSolutionName() +'.group');
			}
			else
				application.setValueListItems('vls_ma_sec_groups', [''], [-1]);
		}
		
		application.setUserProperty(application.getSolutionName() +'.username',vUsername)
		application.setUserProperty(application.getSolutionName() +'.ownername',vOwner)
		elements.error.text = null;
		
		//for keeping track of logged in users per owner
		application.addClientInfo(_return.owner_id)
	}	
	else	
	{
		if(_return.error)
		{
			elements.error.text = i18n.getI18NMessage(_return.error)
		}
		else
		{
			elements.error.text = i18n.getI18NMessage('svy.fr.dlg.loginfailed')
		}
	}
	return;
}

/**
 * @properties={typeid:24,uuid:"FF8B399D-9EDC-44AB-B511-AE5710A70A30"}
 */
function loginWithCAS()
{
	// TODO old function to maintain compatibility with previous version
}

/**
 * @param {Object} [oldValue]
 * @param {Object} [newValue]
 *
 * @properties={typeid:24,uuid:"CF85072F-54E1-4EDE-A77B-5BF83A1EB643"}
 */
function loginWithOrganization(oldValue, newValue)
{
	application.setUserProperty(application.getSolutionName() +'.group', vGroup && vGroup.toString());	
	globals.ma_sec_lgn_groupid = vGroup;
	
	// if a group is selected that's the only group we can after select 
	if(newValue)
	{
		var newDisplayValue = application.getValueListDisplayValue('vls_ma_sec_groups',newValue);
		application.setValueListItems('vls_ma_sec_groups', [newDisplayValue], [newValue]);
	}
		
	return _super.loginWithOrganization(oldValue, newValue)
}

/**
 * TODO generated, please specify type and doc for the params
 * @param userid
 * @param ownerid
 *
 * @properties={typeid:24,uuid:"03C372E0-69FC-42DD-868F-85F6908EB2B5"}
 */
function loginWithCasId(userid,ownerid)
{
	// TODO 
}

/**
 * @properties={typeid:24,uuid:"B5015AB8-C9C2-44A1-ACD8-4536BF0AACB1"}
 */
function loginWithCasStd(username,password,owner,organization)
{
	vUsername = username;
	vPassword = password;
	vOwner = owner;
	vOrganization = organization;
	
	//check if user name and password are entered
	if((!vUsername) || (!vPassword) || (!vOwner))
	{
		globals.ma_utl_showErrorDialog(i18n.getI18NMessage('svy.fr.dlg.username_password_entered'),'Login');
		return
	}
	
	if(vOrganization && !vGroup)
	{
		globals.ma_utl_showErrorDialog(i18n.getI18NMessage('ma.aut.msg.group_not_entered'),'Login');
		return;
	}
	
	if (!vFirstLoginAttempt) {
		vFirstLoginAttempt = new Date();
	}	
	
	//user is already choosing organization
	if(vUser_id && vOrganization)
	{	
		//login the organization
		loginWithOrganization();
		return;
	}	

	// Call authentication module/method, authentication is done on server not on the client.
	var _authObj = new Object()
	_authObj.username = vUsername
	_authObj.password = vPassword
	_authObj.owner = vOwner
	_authObj.firstLoginAttempt = vFirstLoginAttempt
	_authObj.lastLoginAttempt = vLastLoginAttempt
	_authObj.framework_db = vFramework_db
	
	/** @type {{owner_id:String,user_id:String,error:String, success:Boolean}} */
	var _return = security.authenticate('svy_sec_authenticate', 'svy_sec_checkUserPassword',[_authObj])
	if(_return.success)
	{
		// set user id
		globals.svy_sec_lgn_user_id = _return.user_id
		
		// set owner id
		globals.svy_sec_lgn_owner_id = _return.owner_id
		
		// check whether the owner can access this solution
		if (!isOwnerEnabled())
		{
			globals.ma_utl_logError('i18n:ma.psl.err.auth.user_not_enabled', LOGGINGLEVEL.FATAL);
			globals.ma_utl_showErrorDialog(i18n.getI18NMessage('ma.psl.err.auth.user_not_enabled'),'Login');
			
			return;
		}

		// TODO go on from here ----------------------------------------------------------------
		
		// get organizations, if there are multiple organizations for this user he has to choose his organization
		/** @type {JSDataSet} */
		var _dat_org =  security.authenticate('svy_sec_authenticate', 'svy_sec_getOrganizations', [_return.user_id, _return.owner_id, vFramework_db])

		// set organization valuelist
		vUser_id = _return.user_id
		if(_dat_org.getMaxRowIndex() == 1)
		{
			vOrganization = _dat_org.getValue(1,2);
			setGroupValueList(null, vOrganization);
			loginWithOrganization();
		    return;
		}
		else
		{
			application.setValueListItems('svy_sec_lgn_organizations',_dat_org,true)
			elements.lbl_organization.visible = true
			elements.fld_organization.visible = true
		}
		
		/**
		 * Retrieve the stored organization only if it's the same owner
		 */
		if(vOwner === application.getUserProperty(application.getSolutionName() +'.ownername'))
		{
			// enter the organization id
			if(application.getUserProperty(application.getSolutionName() +'.organization')
				&& _dat_org.getColumnAsArray(2).indexOf(application.getUserProperty(application.getSolutionName() +'.organization') > -1))
				vOrganization = application.getUserProperty(application.getSolutionName() +'.organization')
		
		}
		else
			elements.fld_organization.requestFocus()

		// MA_Variazione : tolta selezione del gruppo di appartenenza in ingresso
		if(globals.ma_utl_hasModule(globals.Module.AUTORIZZAZIONI))
		{
//			elements.lbl_group.visible = true
//			elements.fld_group.visible = true
			
			if(vOrganization)
			{
				setGroupValueList(null, vOrganization);
//				if(application.getUserProperty(application.getSolutionName() +'.group'))
//					vGroup = application.getUserProperty(application.getSolutionName() +'.group');
			}
			else
				application.setValueListItems('vls_ma_sec_groups', [''], [-1]);
		}
		
		application.setUserProperty(application.getSolutionName() +'.username',vUsername)
		application.setUserProperty(application.getSolutionName() +'.ownername',vOwner)
		elements.error.text = null;
		
		//for keeping track of logged in users per owner
		application.addClientInfo(_return.owner_id)
	}	
	else	
	{
		if(_return.error)
		{
			elements.error.text = i18n.getI18NMessage(_return.error)
		}
		else
		{
			elements.error.text = i18n.getI18NMessage('svy.fr.dlg.loginfailed')
		}
	}
	return;
}

/**
 * @properties={typeid:24,uuid:"C342E337-EDD9-4215-9F16-CB3C1698EFE0"}
 */
function logoutWithCAS()
{
	globals.ma_sec_cas_logout();
}

/**
 * @properties={typeid:24,uuid:"A28EB805-F6FD-47C4-88AE-203F2BE9E997"}
 */
function exit()
{
	// Logout from CAS
	if(globals.is_cas_authenticated)
		logoutWithCAS();
	else	
		application.closeSolution(application.getSolutionName());
}
/**
 * Handle changed data.
 *
 * @param {String} oldValue old value
 * @param {String} newValue new value
 * @param {JSEvent} event the event that triggered the action
 *
 * @returns {Boolean}
 *
 * @private
 *
 * @properties={typeid:24,uuid:"B5304F54-49E9-4B9C-9852-2A2EEE643A03"}
 */
function onDataChangeUsername(oldValue, newValue, event) {
	
	if(oldValue && oldValue != newValue && vPassword)
		exit();
	
	return true
}

/**
 * Handle changed data.
 *
 * @param {String} oldValue old value
 * @param {String} newValue new value
 * @param {JSEvent} event the event that triggered the action
 *
 * @returns {Boolean}
 *
 * @private
 *
 * @properties={typeid:24,uuid:"89617991-5D27-4B03-B742-9FB6679993CE"}
 */
function onDataChangeOwner(oldValue, newValue, event) {
	
	if(oldValue && oldValue != newValue	&& vUsername && vPassword)
		exit();
	
	return true
}

/**
 * TODO generated, please specify type and doc for the params
 * @param message
 *
 * @properties={typeid:24,uuid:"E8179D00-D4FA-4C79-98C2-5F3B1756A131"}
 */
function showMessage(message)
{
	elements.error.text = message;
}

/**
 * @properties={typeid:24,uuid:"D878D35E-4AF5-4A92-84E8-DD6014F16F0F"}
 */
function isOwnerEnabled()
{
	return true;
}

/**
 * Perform the element default action.
 *
 * @param {JSEvent} event the event that triggered the action
 *
 * @protected 
 *
 * @properties={typeid:24,uuid:"D2A0736C-B6E1-4B18-9FFF-2C9FDCEEAA77"}
 * @AllowToRunInFind
 */
function onAction$btn_recupera_password(event) 
{
	var answer = globals.ma_utl_showYesNoQuestion('Desideri ricevere via email una nuova password per la coppia utente/proprietario specificata?','Recupera password');
	if(!answer)
		return;
	
	// trova il record di sec_user corrispondente
	/** @type {JSFoundset<db:/svy_framework/sec_user>}*/
	var fs = databaseManager.getFoundSet(globals.Server.SVY_FRAMEWORK,'sec_user');
	if(fs.find())
	{
		fs.user_name = vUsername;
		fs.sec_user_to_sec_owner.name = vOwner;
		if(fs.search() == 1) // corrispondenza univoca utente - proprietario
		{
			var recUser = fs.getSelectedRecord();
			
			// genera la nuova password
			var newPwd = globals.ma_utl_generatePwd();
			// salva la nuova password
			globals.svy_sec_setUserPassword(recUser,newPwd,newPwd);
			var mailAddress = fs.getSelectedRecord().com_email;
			if(mailAddress && plugins.mail.isValidEmailAddress(mailAddress))
			{
				var properties = globals.setSparkPostSmtpProperties();
				var subject = "Presenza Semplice Studio Miazzo - Comunicazione nuova password per accesso all\'applicativo";
				var userName = recUser.name_first_names && recUser.name_last ? recUser.name_first_names + " " + recUser.name_last : recUser.user_name
				var msgText = msgText += "<head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"></head>";
				msgText += "plain msg<html><head></head><body>Gentile <b>" + userName;
				msgText += "</b>, <br/>";
			    msgText += "in seguito alla sua richiesta le comunichiamo la nuova password per l\'accesso all'applicativo. <br/>";
			    msgText += "La nuova password è la seguente <b><i>: " + newPwd + "</i></b>.<br/><br/>";
			    msgText += "Le ricordiamo che potrà modificare la sua password una volta autenticato, tramite la funzionalità 'Cambia password'.<br/><br/>";
			    msgText += "Cordiali saluti.</body></html>";
				
				var success = plugins.mail.sendMail
				(mailAddress,
					'Gestore autorizzazioni <assistenza@studiomiazzo.it>',
					subject,
					msgText,
					null,
					null,
					null,
					properties);
				if (!success)
				{
					application.output('Invio comunicazione non riuscito',LOGGINGLEVEL.ERROR);
					globals.ma_utl_showWarningDialog(plugins.mail.getLastSendMailExceptionMsg(), 'Comunicazione nuova password');
				}
			}
			else
			{
				globals.ma_utl_showWarningDialog('Indirizzo email non valido. Contattare il gestore delle utenze o lo Studio.', 'Recupero password');
				return;
			}
		}
		else
		{
			globals.ma_utl_showWarningDialog('Nessun utente corrispondente. Controllare i dati inseriti per utente e proprietario', 'Recupero password');
			return;
		}
	}
		
	// TODO invia alla mail associata la comunicazione con la nuova password (temporanea?...)
}

/**
 * Perform the element default action.
 *
 * @param {JSEvent} event the event that triggered the action
 *
 * @protected
 *
 * @properties={typeid:24,uuid:"69388020-6865-4E8E-9CAA-42EE1D46554C"}
 */
function onAction$btn_exit(event) 
{		
	exit();
}
