<?php
/**
 * Default settings for the haveapi plugin
 *
 * @author Jakub Skokan <jakub.skokan@vpsfree.cz>
 */

$conf['api_url']             = 'https://your.api.tld';
$conf['api_version']         = null;
$conf['client_identity']     = 'haveapi-dokuwiki';
$conf['request_user']        = 'user';
$conf['request_password']    = 'password';
$conf['user_resource']       = null;
$conf['user_current_action'] = 'current';
$conf['user_name']           = 'full_name';
$conf['user_mail']           = 'email';
$conf['grp_admin_param']     = 'level';
$conf['grp_admin_param_cmp'] = '==';
$conf['grp_admin_cmp_with']  = '';
$conf['default_groups']      = 'user';
