<?php
/**
 * DokuWiki Plugin haveapi (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Jakub Skokan <jakub.skokan@vpsfree.cz>
 */

if(!defined('DOKU_INC')) die();

class action_plugin_haveapi extends DokuWiki_Action_Plugin {
    private $helper;

    public function __construct() {
        $this->helper = $this->loadHelper('haveapi');
    }

    public function register(Doku_Event_Handler $controller) {
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

    public function onActionActPreprocess(Doku_Event $event, $param) {
        global $ID;

        if ($event->data == 'login' || $event->data == 'logout') {
            return;

        } elseif ($event->data == 'haveapi_auth' && $this->isAuthenticationOpen()) {
            $event->preventDefault();

            if ($this->isPostRequest())
                $this->processAuthForm();

        } elseif (!$this->isAuthenticationComplete()) {
            send_redirect(wl($ID, ['do' => 'haveapi_auth'], true, '&'));
        }
    }

    public function onTplActUnknown(Doku_Event $event, $param) {
        if ($event->data == 'haveapi_auth') {
            $event->preventDefault();
            $this->showAuthForm();
        }
    }

    private function isPostRequest() {
        global $INPUT;
        return $INPUT->server->str('REQUEST_METHOD') === 'POST';
    }

    private function isAuthenticationOpen() {
        return isset($_SESSION[DOKU_COOKIE][HAVEAPI_AUTH]);
    }

    private function isAuthenticationComplete() {
        return !$this->isAuthenticationOpen()
               || !$_SESSION[DOKU_COOKIE][HAVEAPI_AUTH]['auth_open'];
    }

    private function processAuthForm() {
        global $ID, $INPUT;

        $conf = $this->getAuthConf();
        $input = [];

        foreach ($conf['credentials'] as $name) {
            $input[$name] = $INPUT->post->str($name);
        }

        $step = $conf['step'];

        try {
            $this->helper->getClient()->authenticate(
                'token',
                [
                    'resume' => [
                        'action' => $conf['next_action'],
                        'token' => $conf['auth_token'],
                        'input' => $input,
                    ],
                    'callback' => $this->helper->getAuthCallback($conf['user']),
                ]
            );
        } catch (HaveAPI\Client\Exception\ActionFailed $e) {
            $_SESSION[DOKU_COOKIE][HAVEAPI_AUTH]['error'] = $e->getMessage();
            return;
        }

        if ($conf['step'] == $step) {
            session_start();
            $this->helper->loginUser($conf['user']);
            session_write_close();
            send_redirect(wl('start', ['do' => 'show'], true, '&'));
            return;
        }
    }

    private function showAuthForm() {
        $conf = $this->getAuthConf();

        $form = new Doku_Form(['id' => 'haveapi_auth']);
        $form->startFieldset($this->getLang('auth_form_title'));

        foreach ($conf['credentials'] as $name) {
            $form->addElement(form_makeTextField(
                $name,
                '',
                $name,
                '',
                'block',
                ['size'=>'50', 'autocomplete'=>'off']
            ));
        }

    	$form->addElement(form_makeButton('submit', '', $this->getLang('login_btn')));
        $form->endFieldset();

        echo '<h1 class="sectionedit1">'.$this->getLang('multifactor_auth').'</h1>';
        echo '<div class="centeralign">'.NL;

        if ($conf['error'])
            echo '<p>'.$conf['error'].'</p>'.NL;

        echo $form->getForm();
        echo '</div>'.NL;
    }

    private function getAuthConf() {
        return $_SESSION[DOKU_COOKIE][HAVEAPI_AUTH];
    }
}
