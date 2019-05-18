<?php
/**
 * DokuWiki Plugin haveapi (Helper Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Jakub Skokan <jakub.skokan@vpsfree.cz>
 */

if(!defined('DOKU_INC')) die();

require_once DOKU_INC . 'lib/plugins/haveapi/vendor/httpful.phar';
require_once DOKU_INC . 'lib/plugins/haveapi/vendor/haveapi-client-php/bootstrap.php';

class helper_plugin_haveapi extends DokuWiki_Plugin {
    private $api;

    public function getClient() {
        if (!$this->api) {
            $this->api = new \HaveAPI\Client(
                $this->getConf('api_url'),
                $this->getConf('api_version'),
                $this->getConf('client_identity')
            );
        }

        return $this->api;
    }

    public function getAuthCallback($user) {
        return function ($action, $token, $params) use ($user) {
            if (isset($_SESSION[DOKU_COOKIE][HAVEAPI_AUTH]))
                $step = $_SESSION[DOKU_COOKIE][HAVEAPI_AUTH]['step'] + 1;
            else
                $step = 0;

            $_SESSION[DOKU_COOKIE][HAVEAPI_AUTH] = [
                'user' => $user,
                'auth_open' => true,
                'next_action' => $action,
                'auth_token' => $token,
                'credentials' => $params,
                'step' => $step,
            ];
            return 'stop';
        };
    }

    public function loginUser($user) {
        $user_res = $this->getConf('user_resource');

        if ($user_res) {
            $reply = $this->getClient()->{$user_res}->{$this->getConf('user_current_action')}->call();

            $USERINFO['name'] = $reply->{$this->getConf('user_name')};
            $USERINFO['mail'] = $reply->{$this->getConf('user_mail')};
            $USERINFO['grps'] = explode(',', $this->getConf('default_groups'));

            if ($this->_isAdmin($reply->{$this->getConf('grp_admin_param')}))
                $USERINFO['grps'][] = 'admin';

        } else {
            $USERINFO['name'] = $user;
            $USERINFO['mail'] = '';
            $USERINFO['grps'] = array();
        }

        $_SERVER['REMOTE_USER'] = $user;

        $_SESSION[DOKU_COOKIE]['auth']['user'] = $user;
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
        $_SESSION[DOKU_COOKIE]['auth']['haveapi_token'] = $this->getClient()->getAuthenticationProvider()->getToken();

        $this->resetAuthentication();
    }

    public function resetAuthentication() {
        if (isset($_SESSION[DOKU_COOKIE][HAVEAPI_AUTH]))
            $_SESSION[DOKU_COOKIE][HAVEAPI_AUTH] = null;
    }

    private function _isAdmin($lvl) {
        $v = $this->getConf('grp_admin_cmp_with');

        switch ($this->getConf('grp_admin_param_cmp')) {
            case '<':
                return $lvl < $v;
            case '<=':
                return $lvl <= $v;
            case '==':
                return $lvl == $v;
            case '!=':
                return $lvl != $v;
            case '>=':
                return $lvl >= $v;
            case '>':
                return $lvl > $v;
            default:
                return false;
        }
    }
}
