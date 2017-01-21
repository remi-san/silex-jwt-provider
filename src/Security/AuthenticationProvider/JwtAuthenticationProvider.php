<?php

namespace RemiSan\Silex\JWT\Security\AuthenticationProvider;

use RemiSan\Silex\JWT\Security\Exception\JwtDecodeUnexpectedValueException;
use RemiSan\Silex\JWT\Security\JwtUserBuilder;
use RemiSan\Silex\JWT\Security\Token\JwtToken;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class JwtAuthenticationProvider implements AuthenticationProviderInterface
{
    /** @var JwtUserBuilder */
    private $userBuilder;
    
    /**
     * Constructor.
     *
     * @param JwtUserBuilder $userBuilder
     */
    public function __construct(JwtUserBuilder $userBuilder)
    {
        $this->userBuilder = $userBuilder;
    }
    
    /**
     * Attempts to authenticate a TokenInterface object.
     *
     * @param TokenInterface $token The TokenInterface instance to authenticate
     *
     * @return TokenInterface An authenticated TokenInterface instance, never null
     *
     * @throws AuthenticationException if the authentication fails
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$token instanceof JwtToken) {
            throw new AuthenticationException(sprintf('%s works only for JwtToken', __CLASS__));
        }
        
        if (!$token->getCredentials()) {
            throw new AuthenticationException('JwtToken must contain a token in order to authenticate.');
        }
        
        try {
            $user = $this->userBuilder->buildUserFromToken($token->getCredentials());
        } catch (JwtDecodeUnexpectedValueException $e) {
            throw new AuthenticationException('Failed to decode the Jwt');
        }

        $authenticatedToken = new JwtToken($user->getRoles());
        $authenticatedToken->setUser($user);
        $authenticatedToken->setAuthenticated(true);

        return $authenticatedToken;
    }
    
    /**
     * Checks whether this provider supports the given token.
     *
     * @param TokenInterface $token A TokenInterface instance
     *
     * @return bool true if the implementation supports the Token, false otherwise
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof JwtToken;
    }
}
