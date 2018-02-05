/**
 * Callback method for when solution is opened.
 * When deeplinking into solutions, the argument part of the deeplink url will be passed in as the first argument
 * All query parameters + the argument of the deeplink url will be passed in as the second argument
 * For more information on deeplinking, see the chapters on the different Clients in the Deployment Guide.
 *
 * @param {String} arg startup argument part of the deeplink url with which the Client was started
 * @param {Object<Array<String>>} queryParams all query parameters of the deeplink url with which the Client was started
 *
 * @properties={typeid:24,uuid:"2B428826-2713-4FC6-A0FB-2C9705FF3287"}
 */
function ma_sec_login_onSolutionOpen(arg, queryParams) {
	globals.svy_nav_lgn_onSolutionOpen(arg);
	scopes.shared.Setup();
}