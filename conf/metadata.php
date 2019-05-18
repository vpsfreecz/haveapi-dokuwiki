<?php
/**
 * Options for the haveapi plugin
 *
 * @author Jakub Skokan <jakub.skokan@vpsfree.cz>
 */


$meta['api_url'] = array('string');
$meta['api_version'] = array('string');
$meta['client_identity'] = array('string');
$meta['request_user'] = array('string');
$meta['request_password'] = array('string');
$meta['user_resource'] = array('string');
$meta['user_current_action'] = array('string');
$meta['user_name'] = array('string');
$meta['user_mail'] = array('string');
$meta['grp_admin_param']     = array('string');
$meta['grp_admin_param_cmp'] = array('multichoice', '_choices' => array('<', '<=', '==', '!=', '>=', '>'));
$meta['grp_admin_cmp_with']  = array('string');
$meta['default_groups'] = array('string');
