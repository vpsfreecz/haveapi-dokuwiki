<?php
/**
 * DokuWiki Plugin haveapi (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Jakub Skokan <jakub.skokan@vpsfree.cz>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

define('HAVEAPI_AUTH', 'haveapi_auth');

class auth_plugin_haveapi extends DokuWiki_Auth_Plugin {

    private $helper;
    private $api;
    private $token;

    /**
     * Constructor.
     */
    public function __construct() {
        parent::__construct(); // for compatibility

        // Set capabilities
        //$this->cando['addUser']     = false; // can Users be created?
        //$this->cando['delUser']     = false; // can Users be deleted?
        //$this->cando['modLogin']    = false; // can login names be changed?
        //$this->cando['modPass']     = false; // can passwords be changed?
        //$this->cando['modName']     = false; // can real names be changed?
        //$this->cando['modMail']     = false; // can emails be changed?
        //$this->cando['modGroups']   = false; // can groups be changed?
        //$this->cando['getUsers']    = false; // can a (filtered) list of users be retrieved?
        //$this->cando['getUserCount']= false; // can the number of users be retrieved?
        //$this->cando['getGroups']   = false; // can a list of available groups be retrieved?
        $this->cando['external']    = true; // does the module do external auth checking?
        $this->cando['logout']      = true; // can the user logout again? (eg. not possible with HTTP auth)

//         if ($this->getConf('user_resource')) {
//             $this->cando['getUsers'] = true;
//         }


        $this->helper = $this->loadHelper('haveapi');
        $this->api = $this->helper->getClient();
        $this->success = true;
    }


    /**
     * Log off the current user [ OPTIONAL ]
     */
    public function logOff() {
        $this->helper->resetAuthentication();

        if (!isset($_SESSION[DOKU_COOKIE]['auth']['haveapi_token']))
            return;

        $this->helper->getClient()->authenticate(
            'token',
            ['token' => $_SESSION[DOKU_COOKIE]['auth']['haveapi_token']]
        );

        try {
            $this->helper->getClient()->logout();

        } catch (HaveAPI\Client\Exception\AuthenticationFailed $e) {
            // token is no longer valid, ignore
        }

        unset($_SESSION[DOKU_COOKIE]['auth']['haveapi_token']);
    }

    /**
     * Do all authentication [ OPTIONAL ]
     *
     * @param   string  $user    Username
     * @param   string  $pass    Cleartext Password
     * @param   bool    $sticky  Cookie should not expire
     * @return  bool             true on successful auth
     */
    public function trustExternal($user, $pass, $sticky = false) {
        global $USERINFO;
        global $conf;
        $sticky ? $sticky = true : $sticky = false; //sanity check

        // user not provided
        if (empty($user)) {
            if (!empty($_SESSION[DOKU_COOKIE]['auth']['info'])) {
                $USERINFO['name'] = $_SESSION[DOKU_COOKIE]['auth']['info']['name'];
                $USERINFO['mail'] = $_SESSION[DOKU_COOKIE]['auth']['info']['mail'];
                $USERINFO['grps'] = $_SESSION[DOKU_COOKIE]['auth']['info']['grps'];
                $_SERVER['REMOTE_USER'] = $_SESSION[DOKU_COOKIE]['auth']['user'];

                return true;
            }

            return false;

        } else { // authenticate
            try {
                $input = array(
                    'user' => $user,
                    'password' => $pass,
                    'callback' => $this->helper->getAuthCallback($user),
                );

                if ($sticky) {
                    // token will be valid for 14 days from last activity
                    $input['interval'] = 14*24*60*60;
                }

                $this->helper->getClient()->authenticate('token', $input);

                if (isset($_SESSION[DOKU_COOKIE][HAVEAPI_AUTH])) {
                    $this->interimLogin($user);
                } else {
                    $this->helper->loginUser($user);
                }

            } catch (HaveAPI\Client\Exception\ActionFailed $e) {
                return false;
            }

            return true;
        }
    }

    /**
     * Return user info
     *
     * Returns info about the given user needs to contain
     * at least these fields:
     *
     * name string  full name of the user
     * mail string  email addres of the user
     * grps array   list of groups the user is in
     *
     * @param   string $user the user name
     * @return  array containing user data or false
     */
    public function getUserData($user) {
        return false;
    }

    /**
     * Create a new User [implement only where required/possible]
     *
     * Returns false if the user already exists, null when an error
     * occurred and true if everything went well.
     *
     * The new user HAS TO be added to the default group by this
     * function!
     *
     * Set addUser capability when implemented
     *
     * @param  string     $user
     * @param  string     $pass
     * @param  string     $name
     * @param  string     $mail
     * @param  null|array $grps
     * @return bool|null
     */
    //public function createUser($user, $pass, $name, $mail, $grps = null) {
        // FIXME implement
    //    return null;
    //}

    /**
     * Modify user data [implement only where required/possible]
     *
     * Set the mod* capabilities according to the implemented features
     *
     * @param   string $user    nick of the user to be changed
     * @param   array  $changes array of field/value pairs to be changed (password will be clear text)
     * @return  bool
     */
    //public function modifyUser($user, $changes) {
        // FIXME implement
    //    return false;
    //}

    /**
     * Delete one or more users [implement only where required/possible]
     *
     * Set delUser capability when implemented
     *
     * @param   array  $users
     * @return  int    number of users deleted
     */
    //public function deleteUsers($users) {
        // FIXME implement
    //    return false;
    //}

    /**
     * Bulk retrieval of user data [implement only where required/possible]
     *
     * Set getUsers capability when implemented
     *
     * @param   int   $start     index of first user to be returned
     * @param   int   $limit     max number of users to be returned
     * @param   array $filter    array of field/pattern pairs, null for no filter
     * @return  array list of userinfo (refer getUserData for internal userinfo details)
     */
    //public function retrieveUsers($start = 0, $limit = -1, $filter = null) {
        // FIXME implement
    //    return array();
    //}

    /**
     * Return a count of the number of user which meet $filter criteria
     * [should be implemented whenever retrieveUsers is implemented]
     *
     * Set getUserCount capability when implemented
     *
     * @param  array $filter array of field/pattern pairs, empty array for no filter
     * @return int
     */
    //public function getUserCount($filter = array()) {
        // FIXME implement
    //    return 0;
    //}

    /**
     * Define a group [implement only where required/possible]
     *
     * Set addGroup capability when implemented
     *
     * @param   string $group
     * @return  bool
     */
    //public function addGroup($group) {
        // FIXME implement
    //    return false;
    //}

    /**
     * Retrieve groups [implement only where required/possible]
     *
     * Set getGroups capability when implemented
     *
     * @param   int $start
     * @param   int $limit
     * @return  array
     */
    //public function retrieveGroups($start = 0, $limit = 0) {
        // FIXME implement
    //    return array();
    //}

    /**
     * Return case sensitivity of the backend
     *
     * When your backend is caseinsensitive (eg. you can login with USER and
     * user) then you need to overwrite this method and return false
     *
     * @return bool
     */
    public function isCaseSensitive() {
        return true;
    }

    /**
     * Sanitize a given username
     *
     * This function is applied to any user name that is given to
     * the backend and should also be applied to any user name within
     * the backend before returning it somewhere.
     *
     * This should be used to enforce username restrictions.
     *
     * @param string $user username
     * @return string the cleaned username
     */
    public function cleanUser($user) {
        return $user;
    }

    /**
     * Sanitize a given groupname
     *
     * This function is applied to any groupname that is given to
     * the backend and should also be applied to any groupname within
     * the backend before returning it somewhere.
     *
     * This should be used to enforce groupname restrictions.
     *
     * Groupnames are to be passed without a leading '@' here.
     *
     * @param  string $group groupname
     * @return string the cleaned groupname
     */
    public function cleanGroup($group) {
        return $group;
    }

    /**
     * Check Session Cache validity [implement only where required/possible]
     *
     * DokuWiki caches user info in the user's session for the timespan defined
     * in $conf['auth_security_timeout'].
     *
     * This makes sure slow authentication backends do not slow down DokuWiki.
     * This also means that changes to the user database will not be reflected
     * on currently logged in users.
     *
     * To accommodate for this, the user manager plugin will touch a reference
     * file whenever a change is submitted. This function compares the filetime
     * of this reference file with the time stored in the session.
     *
     * This reference file mechanism does not reflect changes done directly in
     * the backend's database through other means than the user manager plugin.
     *
     * Fast backends might want to return always false, to force rechecks on
     * each page load. Others might want to use their own checking here. If
     * unsure, do not override.
     *
     * @param  string $user - The username
     * @return bool
     */
    //public function useSessionCache($user) {
      // FIXME implement
    //}

    private function interimLogin($user) {
        $USERINFO['name'] = $user;
        $USERINFO['mail'] = '';
        $USERINFO['grps'] = array();

        $_SERVER['REMOTE_USER'] = $user;

        $_SESSION[DOKU_COOKIE]['auth']['user'] = $user;
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
    }
}

// vim:ts=4:sw=4:et:
