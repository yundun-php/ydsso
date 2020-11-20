<?php
namespace Jasny\SSO;

use Desarrolla2\Cache\Cache;
use Desarrolla2\Cache\Adapter;
use Response\Response;

/**
 * Single sign-on server.
 *
 * The SSO server is responsible of managing users sessions which are available for brokers.
 *
 * To use the SSO server, extend this class and implement the abstract methods.
 * This class may be used as controller in an MVC application.
 */
abstract class Server
{
    /**
     * @var array
     */
    protected $options;

    /**
     * Cache that stores the special session data for the brokers.
     *
     * @var Cache
     */
    protected $cache;

    /**
     * @var string
     */
    protected $returnType;

    /**
     * @var mixed
     */
    protected $brokerId;


    /**
     * Class constructor
     *
     * @param array $options
     */
    public function __construct(array $options = [])
    {
        $this->options = $options;
        $this->cache = $this->createCacheAdapter();
    }

    /**
     * Create a cache to store the broker session id.
     *
     * @return Cache
     */
    protected function createCacheAdapter()
    {
        $adapter = new Adapter\File('/tmp');
        $adapter->setOption('ttl', 10 * 3600);

        return new Cache($adapter);
    }

    /**
     * Start the session for broker requests to the SSO server
     */
    public function startBrokerSession()
    {
        if (isset($this->brokerId)) return;

        if (!isset($_GET['sso_session'])) {
            return $this->fail("Broker didn't send a session key", 400);
        }

        $sid = $_GET['sso_session'];

        $linkedId = $this->cache->get($sid);

        if (!$linkedId) {
            return $this->fail("The broker session id isn't attached to a user session", 403);
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            if ($linkedId !== session_id()) throw new \Exception("Session has already started", 400);
            return;
        }

        session_id($linkedId);
        session_start();

        $this->brokerId = $this->validateBrokerSessionId($sid);
    }

    /**
     * Validate the broker session id
     *
     * @param string $sid session id
     * @return string  the broker id
     */
    protected function validateBrokerSessionId($sid)
    {
        $matches = null;

        if (!preg_match('/^SSO-(\w*+)-(\w*+)-([a-z0-9]*+)$/', $_GET['sso_session'], $matches)) {
            return $this->fail("Invalid session id");
        }

        $brokerId = $matches[1];
        $token = $matches[2];

        if ($this->generateSessionId($brokerId, $token) != $sid) {
            return $this->fail("Checksum failed: Client IP address may have changed", 403);
        }

        return $brokerId;
    }

    /**
     * Start the session when a user visits the SSO server
     */
    protected function startUserSession()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    }

    /**
     * Generate session id from session token
     *
     * @param string $brokerId
     * @param string $token
     * @return string
     */
    protected function generateSessionId($brokerId, $token)
    {
        $broker = $this->getBrokerInfo($brokerId);

        if (!isset($broker)) return null;

        return "SSO-{$brokerId}-{$token}-" . hash('sha256', 'session' . $token . $broker['secret']);
    }

    /**
     * Generate session id from session token
     *
     * @param string $brokerId
     * @param string $token
     * @return string
     */
    protected function generateAttachChecksum($brokerId, $token)
    {
        $broker = $this->getBrokerInfo($brokerId);

        if (!isset($broker)) return null;

        return hash('sha256', 'attach' . $token . $broker['secret']);
    }


    /**
     * Detect the type for the HTTP response.
     * Should only be done for an `attach` request.
     */
    protected function detectReturnType()
    {
        if (!empty($_GET['return_url'])) {
            $this->returnType = 'redirect';
        } elseif (!empty($_GET['callback'])) {
            $this->returnType = 'jsonp';
        } elseif (strpos($_SERVER['HTTP_ACCEPT'], 'image/') !== false) {
            $this->returnType = 'image';
        } elseif (strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) {
            $this->returnType = 'json';
        }
    }

    /**
     * Attach a user session to a broker session
     */
    public function attach()
    {
        $this->detectReturnType();

        if (empty($_REQUEST['broker'])) return $this->fail("No broker specified", 400);
        if (empty($_REQUEST['token'])) return $this->fail("No token specified", 400);

        if (!$this->returnType) return $this->fail("No return url specified", 400);

        $checksum = $this->generateAttachChecksum($_REQUEST['broker'], $_REQUEST['token']);

        if (empty($_REQUEST['checksum']) || $checksum != $_REQUEST['checksum']) {
            return $this->fail("Invalid checksum", 400);
        }

        $this->startUserSession();
        $sid = $this->generateSessionId($_REQUEST['broker'], $_REQUEST['token']);

        $this->cache->set($sid, $this->getSessionData('id'));
        $this->outputAttachSuccess();
    }

    /**
     * Output on a successful attach
     */
    protected function outputAttachSuccess()
    {
        if ($this->returnType === 'image') {
            $this->outputImage();
        }

        if ($this->returnType === 'json') {
	        if ( ! headers_sent() ) {
		        header( 'Content-Type:application/json; charset=utf-8' );
	        }
            echo json_encode(['success' => 'attached']);
        }

        if ($this->returnType === 'jsonp') {
            $data = json_encode(['success' => 'attached']);
	        if ( ! headers_sent() ) {
		        header( 'Content-Type:application/json; charset=utf-8' );
	        }
            echo htmlspecialchars($_REQUEST['callback']) . "($data, 200);";
        }

        if ($this->returnType === 'redirect') {
            $url = $_REQUEST['return_url'];
            header("Location: $url", true, 307);
            echo "You're being redirected to <a href='{$url}'>$url</a>";
        }
    }

    /**
     * Output a 1x1px transparent image
     */
    protected function outputImage()
    {
        header('Content-Type: image/png');
        echo base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQ'
            . 'MAAAAl21bKAAAAA1BMVEUAAACnej3aAAAAAXRSTlMAQObYZg'
            . 'AAAApJREFUCNdjYAAAAAIAAeIhvDMAAAAASUVORK5CYII=');
    }



    /**
     * Ouput user information as json.
     */
    public function userInfo()
    {
        $this->startBrokerSession();
        $user = null;

        $username = $this->getSessionData('sso_user');

        if ($username) {
            $user = $this->getUserInfo($username);
            if (!$user) return $this->fail("User not found", 500); // Shouldn't happen
        }

	    //new style response
	    if(Response::isSSOVersion2()){
		    Response::setCodeConf(Conf::$codeConf);
		    $code = $user ? 1 : Conf::CODE_SESSION_EXPIRE;
		    Response::responseApi($code, $user?$user:[], [], '', 'json', 0, 0);
	    }else{
		    header('Content-type: application/json; charset=UTF-8');
		    echo json_encode($user);
	    }
    }


    /**
     * Set session data
     *
     * @param string $key
     * @param string $value
     */
    protected function setSessionData($key, $value)
    {
        if (!isset($value)) {
            unset($_SESSION[$key]);
            return;
        }

        $_SESSION[$key] = $value;
    }


    /**
     * @param $key
     * @return null|string
     * @node_name Get session data
     * @link
     * @desc
     */
    protected function getSessionData($key)
    {
        if ($key === 'id') return session_id();

        return isset($_SESSION[$key]) ? $_SESSION[$key] : null;
    }



    /**
     * @param string $message
     * @param int $http_status
     * @throws \Exception
     * @node_name An error occured.
     * @link
     * @desc
     */
    protected function fail($message, $http_status = 500)
    {
    	//new style response
    	if(Response::isSSOVersion2()){
    		$code = 0;
    		if($http_status == 403){
    			$code =  Conf::NO_TOKEN_CODE;
		    }
    		Response::setCodeConf(Conf::$codeConf);
    		Response::responseApi($code, [], [$message]);
	    }

        if (!empty($this->options['fail_exception'])) {
            throw new \Exception($message, $http_status);
        }

        if ($http_status === 500) trigger_error($message, E_USER_WARNING);

        if ($this->returnType === 'jsonp') {
            echo $_REQUEST['callback'] . "(" . json_encode(['error' => $message]) . ", $http_status);";
            exit();
        }

        if ($this->returnType === 'redirect') {
            $url = $_REQUEST['return_url'] . '?sso_error=' . $message;
            header("Location: $url", true, 307);
            echo "You're being redirected to <a href='{$url}'>$url</a>";
            exit();
        }

        http_response_code($http_status);
        header('Content-type: application/json; charset=UTF-8');

        echo json_encode(['error' => $message]);
        exit();
    }


    /**
     * Authenticate using user credentials
     *
     * @param string $username
     * @param string $password
     * @param array $params
     * @return \Jasny\ValidationResult
     */
    abstract protected function authenticate($username, $password, $params = []);

    /**
     * Get the secret key and other info of a broker
     *
     * @param string $brokerId
     * @return array
     */
    abstract protected function getBrokerInfo($brokerId);

    /**
     * Get the information about a user
     *
     * @param string $username
     * @return array|object
     */
    abstract protected function getUserInfo($username);


}

