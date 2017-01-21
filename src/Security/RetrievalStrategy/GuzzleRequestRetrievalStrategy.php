<?php

namespace RemiSan\Silex\JWT\Security\RetrievalStrategy;

use Assert\Assertion;
use RemiSan\Silex\JWT\Security\Exception\JwtNotFoundException;
use RemiSan\Silex\JWT\Security\JwtRetrievalStrategy;
use RemiSan\Silex\JWT\Security\Token\JwtToken;
use Guzzle\Http\Message\RequestInterface;

class GuzzleRequestRetrievalStrategy implements JwtRetrievalStrategy
{
    const HTTP_PARAM_JWT = 'jwt';

    /**
     * @param RequestInterface $request
     *
     * @return JwtToken
     *
     * @throws JwtNotFoundException
     */
    public function getToken($request)
    {
        Assertion::isInstanceOf($request, RequestInterface::class);

        $jwtString = $request->getQuery()->get(self::HTTP_PARAM_JWT);

        if ($jwtString === null) {
            throw new JwtNotFoundException();
        }

        $jwtToken = new JwtToken();
        $jwtToken->setToken($jwtString);

        return $jwtToken;
    }

    /**
     * @param mixed $request
     *
     * @return bool
     */
    public function supports($request)
    {
        return $request instanceof RequestInterface;
    }
}
