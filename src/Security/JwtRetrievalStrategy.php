<?php

namespace RemiSan\Silex\JWT\Security;

use RemiSan\Silex\JWT\Security\Exception\JwtNotFoundException;
use RemiSan\Silex\JWT\Security\Token\JwtToken;

interface JwtRetrievalStrategy
{
    /**
     * @param mixed $request
     *
     * @return JwtToken
     *
     * @throws JwtNotFoundException
     */
    public function getToken($request);

    /**
     * @param mixed $request
     *
     * @return bool
     */
    public function supports($request);
}