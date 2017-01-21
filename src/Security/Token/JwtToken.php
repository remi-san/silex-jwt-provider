<?php

namespace RemiSan\Silex\JWT\Security\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class JwtToken extends AbstractToken
{
    /** @var string */
    private $token;

    /**
     * Returns the user credentials.
     *
     * @return mixed The user credentials
     */
    public function getCredentials()
    {
        return $this->token;
    }

    /**
     * @param string $token
     */
    public function setToken($token)
    {
        $this->token = $token;
    }
}
