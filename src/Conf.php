<?php

namespace Jasny\SSO;

class Conf {

	public static $codeConf = [
		1      => "ok",
		0      => "%s",
		100403 => "No token",
		16149  => 'session expired'

	];

	const NO_TOKEN_CODE = 100403;
	const CODE_SESSION_EXPIRE = 16149;


}