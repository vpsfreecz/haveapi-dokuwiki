<?php
/**
 * DokuWiki Plugin haveapi (Action Component)
 *
 * The plugin listens for event AUTH_LOGIN_CHECK and hijacks it. Se the
 * authtype to haveapi as well. The user credentials are used to request token
 * from the HaveAPI based API. If the authentication requires multiple steps,
 * the user is redirected to additional form pages.
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Jakub Skokan <jakub.skokan@vpsfree.cz>
 */

if(!defined('DOKU_INC')) die();

define('HAVEAPI_AUTH', 'haveapi_auth');

class action_plugin_haveapi extends DokuWiki_Action_Plugin {
    private $api;

    public function __construct() {
        require_once DOKU_INC . 'lib/plugins/haveapi/vendor/httpful.phar';
        require_once DOKU_INC . 'lib/plugins/haveapi/vendor/haveapi-client-php/bootstrap.php';
    }

    public function register(Doku_Event_Handler $controller) {
        $controller->register_hook(
            'AUTH_LOGIN_CHECK',
            'BEFORE',
            $this,
            'onAuthLoginCheck'
        );
        $controller->register_hook(
            'ACTION_ACT_PREPROCESS',
            'BEFORE',
            $this,
            'onActionActPreprocess'
        );
        $controller->register_hook(
            'TPL_ACT_UNKNOWN',
            'BEFORE',
            $this,
            'onTplActUnknown'
        );
    }

    /**
     * Continue current session or start a new authentication process
     */
    public function onAuthLoginCheck(Doku_Event &$event, $param) {
        global $ID;

        $event->preventDefault();

        if (empty($event->data['user'])) {
            $event->result = $this->continueSession();
        } else {
            $event->result = $this->beginAuthentication(
                $event->data['user'],
                $event->data['password'],
                $event->data['sticky']
            );
        }
    }

    /**
     * Handle custom authentication steps and logout
     */
    public function onActionActPreprocess(Doku_Event $event, $param) {
        global $ID;

        if ($event->data == 'logout') {
            $this->logout();

        } elseif ($event->data == 'haveapi_auth' && $this->isAuthenticationOpen()) {
            $event->preventDefault();

            if ($this->isPostRequest())
                $this->processAuthForm();
        }
    }

    /**
     * Render custom authentication forms
     */
    public function onTplActUnknown(Doku_Event $event, $param) {
        if ($event->data == 'haveapi_auth') {
            $event->preventDefault();
            $this->showAuthForm();
        }
    }

    /**
     * Begin a new authentication process by requesting a token
     * @param string $user
     * @param string $password
     * @param boolean $sticky
     * @return boolean
     */
    private function beginAuthentication($user, $password, $sticky) {
        global $ID;

        try {
            $input = [
                'callback' => $this->getAuthCallback($user),
            ];

            $input[$this->getConf('request_user')] = $user;
            $input[$this->getConf('request_password')] = $password;

            if ($sticky) {
                // token will be valid for 14 days from last activity
                $input['interval'] = 14*24*60*60;
            }

            $this->getClient()->authenticate('token', $input);

            if ($this->isAuthenticationComplete()) {
                $this->loginUser($user);
                return true;
            } elseif ($this->isAuthenticationOpen()) {
                session_write_close();
                send_redirect(wl($ID, ['do' => 'haveapi_auth'], true, '&'));
            } else {
                throw new Exception("programming error");
            }

        } catch (HaveAPI\Client\Exception\ActionFailed $e) {
            msg($e->getMessage(), -1);
            return false;
        }
    }

    /**
     * Resume the current session, if there is any
     * @return boolean
     */
    private function continueSession() {
        global $USERINFO;

        if (empty($_SESSION[DOKU_COOKIE]['auth']['info']))
            return false;

        $USERINFO['name'] = $_SESSION[DOKU_COOKIE]['auth']['info']['name'];
        $USERINFO['mail'] = $_SESSION[DOKU_COOKIE]['auth']['info']['mail'];
        $USERINFO['grps'] = $_SESSION[DOKU_COOKIE]['auth']['info']['grps'];
        $_SERVER['REMOTE_USER'] = $_SESSION[DOKU_COOKIE]['auth']['user'];

        return true;
    }

    /**
     * Revoke the session token
     */
    private function logout() {
        $this->resetAuthentication();

        if (!isset($_SESSION[DOKU_COOKIE]['auth']['haveapi_token']))
            return;

        $this->getClient()->authenticate(
            'token',
            ['token' => $_SESSION[DOKU_COOKIE]['auth']['haveapi_token']]
        );

        try {
            $this->getClient()->logout();

        } catch (HaveAPI\Client\Exception\AuthenticationFailed $e) {
            // token is no longer valid, ignore
        }

        unset($_SESSION[DOKU_COOKIE]['auth']['haveapi_token']);
    }

    /**
     * @return boolean
     */
    private function isPostRequest() {
        global $INPUT;
        return $INPUT->server->str('REQUEST_METHOD') === 'POST';
    }

    /**
     * @return boolean
     */
    private function isAuthenticationOpen() {
        return isset($_SESSION[DOKU_COOKIE][HAVEAPI_AUTH]);
    }

    /**
     * @return boolean
     */
    private function isAuthenticationComplete() {
        return $this->getClient()->getAuthenticationProvider()->isComplete();
    }

    /**
     * Continue the authentication process with another action
     */
    private function processAuthForm() {
        global $ID, $INPUT;

        $conf = $this->getAuthConf();
        $input = [];

        foreach ($conf['credentials'] as $name => $desc) {
            $input[$name] = $INPUT->post->str($name);
        }

        try {
            $this->getClient()->authenticate(
                'token',
                [
                    'resume' => [
                        'action' => $conf['next_action'],
                        'token' => $conf['auth_token'],
                        'input' => $input,
                    ],
                    'callback' => $this->getAuthCallback($conf['user']),
                ]
            );
        } catch (HaveAPI\Client\Exception\ActionFailed $e) {
            msg($e->getMessage(), -1);
            return;
        }

        if ($this->isAuthenticationComplete()) {
            session_start();
            $this->loginUser($conf['user']);
            session_write_close();
            send_redirect(wl($conf['page_id'], ['do' => 'show'], true, '&'));
            return;
        }
    }

    /**
     * Render form with custom credentials
     */
    private function showAuthForm() {
        $conf = $this->getAuthConf();

        $form = new Doku_Form(['id' => 'haveapi_auth']);
        $form->startFieldset($this->getLang('auth_form_title'));

        foreach ($conf['credentials'] as $name => $desc) {
            $form->addElement(form_makeTextField(
                $name,
                '',
                $desc->label,
                '',
                'block',
                ['size'=>'50', 'autocomplete'=>'off']
            ));
        }

    	$form->addElement(form_makeButton('submit', '', $this->getLang('login_btn')));
        $form->endFieldset();

        echo '<h1 class="sectionedit1">'.$this->getLang('multifactor_auth').'</h1>';
        echo '<div class="centeralign">'.NL.$form->getForm().'</div>'.NL;
    }

    /**
     * @return array
     */
    private function getAuthConf() {
        return $_SESSION[DOKU_COOKIE][HAVEAPI_AUTH];
    }

    /**
     * @return callable
     */
    private function getAuthCallback($user) {
        return function ($action, $token, $params) use ($user) {
            global $INPUT;

            if (isset($_SESSION[DOKU_COOKIE][HAVEAPI_AUTH]))
                $page_id = $_SESSION[DOKU_COOKIE][HAVEAPI_AUTH]['page_id'];
            else
                $page_id = $INPUT->get->str('id');

            $_SESSION[DOKU_COOKIE][HAVEAPI_AUTH] = [
                'page_id' => $page_id,
                'user' => $user,
                'auth_open' => true,
                'next_action' => $action,
                'auth_token' => $token,
                'credentials' => $params,
            ];
            return 'stop';
        };
    }

    /**
     * @param array $user
     */
    private function loginUser($user) {
        global $USERINFO;

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

    /**
     * Reset the authentication process
     */
    private function resetAuthentication() {
        if (isset($_SESSION[DOKU_COOKIE][HAVEAPI_AUTH]))
            unset($_SESSION[DOKU_COOKIE][HAVEAPI_AUTH]);
    }

    /**
     * @return boolean
     */
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

    /**
     * @return \HaveApi\Client
     */
    private function getClient() {
        if (!$this->api) {
            $this->api = new \HaveAPI\Client(
                $this->getConf('api_url'),
                $this->getConf('api_version'),
                $this->getConf('client_identity')
            );
        }

        return $this->api;
    }
}
