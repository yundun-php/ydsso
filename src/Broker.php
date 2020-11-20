<?php

namespace Jasny\SSO;

use Jasny\ValidationResult;
use Response\Response;

/**
 * Single sign-on broker.
 *
 * The broker lives on the website visited by the user. The broken doesn't have any user credentials stored. Instead it
 * will talk to the SSO server in name of the user, verifying credentials and getting user information.
 */
class Broker
{
    /**
     * Url of SSO server
     * @var string
     */
    protected $url;

    /**
     * My identifier, given by SSO provider.
     * @var string
     */
    public $broker;

    /**
     * My secret word, given by SSO provider.
     * @var string
     */
    protected $secret;

    /**
     * Session token of the client
     * @var string
     */
    public $token;

    /**
     * User info recieved from the server.
     * @var array
     */
    protected $userinfo;

    /**
     * curl http header
     * @var array
     */
    protected $headers;

    /** curl http ssl options
     * @var array
     */
    protected $sslOptions;

    /**
     * sso token 过期时间
     * @var
     */
    protected $tokenExpire;

    /**
     * Url of request sso server ,if set
     * @var
     */
    protected $requestUrl;

    /**
     * Class constructor
     *
     * @param string $url Url of SSO server
     * @param string $broker My identifier, given by SSO provider.
     * @param string $secret My secret word, given by SSO provider.
     * @param string $requestUrl Url of request sso server ,if set
     */
    public function __construct($url, $broker, $secret, $requestUrl = '')
    {
        if (!$url) throw new \InvalidArgumentException("SSO server URL not specified");
        if (!$broker) throw new \InvalidArgumentException("SSO broker id not specified");
        if (!$secret) throw new \InvalidArgumentException("SSO broker secret not specified");

        $this->url    = $url;
        $this->broker = $broker;
        $this->secret = $secret;

        if ($requestUrl) {
            $this->requestUrl = $requestUrl;
        }

        if (isset($_COOKIE[$this->getCookieName()])) $this->token = $_COOKIE[$this->getCookieName()];
    }

    /**
     * Get the cookie name.
     *
     * Note: Using the broker name in the cookie name.
     * This resolves issues when multiple brokers are on the same domain.
     *
     * @return string
     */
    protected function getCookieName()
    {
        return 'sso_token_' . preg_replace('/[_\W]+/', '_', strtolower($this->broker));
    }

    /**
     * Generate session id from session key
     *
     * @return string
     */
    protected function getSessionId()
    {
        if (!isset($this->token)) return null;

        $checksum = hash('sha256', 'session' . $this->token . $this->secret);
        return "SSO-{$this->broker}-{$this->token}-$checksum";
    }

    /**
     * Generate session token
     */
    public function generateToken()
    {
        if (isset($this->token)) return;

        $this->token = base_convert(md5(uniqid(rand(), true)), 16, 36);
        setcookie($this->getCookieName(), $this->token, time() + $this->getSsoTokenExpire(), '/', '', false, true);
    }

    /**
     * Clears session token
     */
    public function clearToken()
    {
        setcookie($this->getCookieName(), null, 1, '/');
        $this->token = null;
    }

    /**
     * @param $expire
     * @node_name 设置sso token 过期时间,单位[s]
     * @link
     * @desc
     */
    public function setSsoTokenExpire($expire)
    {
        if ($expire && $expire > 0) {
            $this->tokenExpire = $expire;
        }
    }

    /**
     * @return int
     * @node_name tokenExpire 默认7200
     * @link
     * @desc
     */
    protected function getSsoTokenExpire()
    {
        return $this->tokenExpire ? (int)$this->tokenExpire : 7200;
    }

    /**
     * Check if we have an SSO token.
     *
     * @return boolean
     */
    public function isAttached()
    {
        return isset($this->token);
    }

    /**
     * Get URL to attach session at SSO server.
     *
     * @param array $params
     * @return string
     */
    public function getAttachUrl($params = [])
    {
        $this->generateToken();

        $data = [
                'command'  => 'attach',
                'broker'   => $this->broker,
                'token'    => $this->token,
                'checksum' => hash('sha256', 'attach' . $this->token . $this->secret)
            ] + $_GET;

        return $this->url . "?" . http_build_query($data + $params);
    }

    /**
     * Attach our session to the user's session on the SSO server.
     *
     * @param string|true $returnUrl The URL the client should be returned to after attaching
     */
    public function attach($returnUrl = null)
    {

        if ($this->isAttached()) return;

        if ($returnUrl === true) {
            $protocol  = !empty($_SERVER['HTTPS']) ? 'https://' : 'http://';
            $returnUrl = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        }

        $params = ['return_url' => $returnUrl];
        $url    = $this->getAttachUrl($params);

        header("Location: $url", true, 307);
        echo "You're redirected to <a href='$url'>$url</a>";
        exit();
    }

    /**
     * Get the request url for a command
     *
     * @param string $command
     * @param array $params Query parameters
     * @return string
     */
    protected function getRequestUrl($command, $params = [])
    {
        $params['command']     = $command;
        $params['sso_session'] = $this->getSessionId();

        $requestUrl = $this->requestUrl ? $this->requestUrl : $this->url;
        return $requestUrl . '?' . http_build_query($params);
    }


    /**
     * @param $method HTTP method: 'GET', 'POST', 'DELETE'
     * @param string $command Command
     * @param array|string $data Query or post parameters
     * @return array|mixed|null|object
     * @throws Exception
     * @throws NotAttachedException
     * @throws \Response\Exceptions\ResponseException
     * @node_name Execute on SSO server.
     * @link
     * @desc
     */
    protected function request($method, $command, $data = null)
    {
	    try {
		    if ( ! $this->isAttached() ) {
			    throw new NotAttachedException( 'No token' );
		    }
		    $url = $this->getRequestUrl( $command, ! $data || $method === 'POST' ? [] : $data );

		    $ch = curl_init( $url );
		    curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
		    curl_setopt( $ch, CURLOPT_CUSTOMREQUEST, $method );
		    $this->setRequestHeaders( 'Accept', 'application/json' );
		    $this->set_request_headers( $ch );
		    $this->setSsl( $ch );

		    if ( $method === 'POST' && ! empty( $data ) ) {
			    $post = is_string( $data ) ? $data : http_build_query( $data );
			    curl_setopt( $ch, CURLOPT_POSTFIELDS, $post );
		    }

		    $response = curl_exec( $ch );
		    if ( curl_errno( $ch ) != 0 ) {
			    $message = 'Server request failed: ' . curl_error( $ch );
			    throw new Exception( $message );
		    }

		    $httpCode = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		    list( $contentType ) = explode( ';', curl_getinfo( $ch, CURLINFO_CONTENT_TYPE ) );

		    if ( $contentType != 'application/json' ) {
			    $message = 'Expected application/json response, got ' . $contentType;
			    throw new Exception( $message );
		    }

		    $responseDecode = json_decode( $response, true );
		    //new style response
		    if ( Response::isSSOVersion2() && isset( $responseDecode['status']['code'] ) && $responseDecode['status']['code'] == Conf::NO_TOKEN_CODE ) {
			    $this->clearToken();
		    }

		    if ( $httpCode == 403 ) {
			    $this->clearToken();
			    throw new NotAttachedException( $responseDecode['error'] ?: $response, $httpCode );
		    }
		    if ( $httpCode >= 400 ) {
			    throw new Exception( $responseDecode['error'] ?: $response, $httpCode );
		    }
	    } catch ( Exception $e ) {
		    //new style response
		    if ( Response::isSSOVersion2() ) {
			    Response::setCodeConf( Conf::$codeConf );
			    if ( $e instanceof NotAttachedException ) {
				    $responseDecode = Response::responseApi( Conf::NO_TOKEN_CODE, [], [], '', 'json', 0, 1, 'js', 1 );
			    } else {
				    $responseDecode = Response::responseApi( 0, [], [$e->getMessage()], '', 'json', 0, 1, 'js', 1 );
			    }

			    return $responseDecode;
		    } else {
			    throw $e;
		    }
	    }

	    return $responseDecode;
    }


    /**
     * @param $key
     * @param $val
     * @node_name 设置请求头
     * @link
     * @desc
     */
    public function setRequestHeaders($key, $val)
    {
        $this->headers[$key] = $val;
    }

    /**
     * @param $ch
     * @node_name Formats and adds custom headers to the current request
     * @link
     * @desc
     */
    protected function set_request_headers($ch)
    {
        $headers = array();
        foreach ($this->headers as $key => $value) {
            $headers[] = $key . ': ' . $value;
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }

    /**
     * @param $ip
     * @node_name 设置ip
     * @link
     * @desc
     */
    public function setRequestIp($ip)
    {
        $this->setRequestHeaders('X-CLIENT-IP', $ip);
    }

    /**
     * @param $userAgent
     * @node_name 设置user agent
     * @link
     * @desc
     */
    public function setRequestUserAgent($userAgent)
    {
        $this->setRequestHeaders('X-USER-AGENT', $userAgent);
    }

    /**
     * @param $caInfo
     * @param int $verifyHost
     * @param bool|true $verifyPeer
     * @node_name 设置ssl证书options
     * @link
     * @desc
     */
    public function setSslOptions($caInfo, $verifyHost = 2, $verifyPeer = true)
    {
        $options = [
            CURLOPT_SSL_VERIFYHOST => $verifyHost,
            CURLOPT_SSL_VERIFYPEER => $verifyPeer,
            CURLOPT_CAINFO         => $caInfo,
        ];

        $this->sslOptions = $options;
    }


    /**
     * @node_name 不使用ssl证书
     * @link
     * @desc
     */
    public function setNoSslOptions()
    {
        $options = [
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ];

        $this->sslOptions = $options;
    }

    /**
     * @param $ch
     * @node_name ssl
     * @link
     * @desc
     */
    protected function setSsl($ch)
    {
        if ($this->sslOptions) {
            curl_setopt_array($ch, $this->sslOptions);
        }
    }




    /**
     * Get user information.
     *
     * @return object|null
     */
    public function getUserInfo()
    {
        if (!isset($this->userinfo)) {
            $this->userinfo = $this->request('GET', 'userInfo', $_GET);
        }

        return $this->userinfo;
    }

    /**
     * Magic method to do arbitrary request
     *
     * @param string $fn
     * @param array $args
     * @return mixed
     */
    public function __call($fn, $args)
    {
        $method = isset($args[0]['method']) ? $args[0]['method'] : 'POST';
        $res    = $this->request($method, $fn, $args[0]['data']);

        return $res;
    }
}
