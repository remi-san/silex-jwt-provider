<?php

namespace RemiSan\Silex\JWT\Security;

use RemiSan\Silex\JWT\Security\Exception\JwtNotFoundException;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

class JwtAuthenticator
{
    /** @var TokenStorageInterface */
    private $tokenStorage;

    /** @var AuthenticationManagerInterface */
    private $authenticationManager;

    /** @var JwtRetrievalStrategy */
    private $jwtRetrievalStrategy;

    /**
     * Constructor.
     *
     * @param TokenStorageInterface          $tokenStorage
     * @param AuthenticationManagerInterface $authenticationManager
     * @param JwtRetrievalStrategy           $jwtRetrievalStrategy
     */
    public function __construct(
        TokenStorageInterface $tokenStorage,
        AuthenticationManagerInterface $authenticationManager,
        JwtRetrievalStrategy $jwtRetrievalStrategy
    ) {
        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
        $this->jwtRetrievalStrategy = $jwtRetrievalStrategy;
    }

    /**
     * @param mixed $request
     */
    public function authenticate($request)
    {
        if (! $this->jwtRetrievalStrategy->supports($request)) {
            return;
        }

        try {
            $jwtToken = $this->jwtRetrievalStrategy->getToken($request);

            $authToken = $this->authenticationManager->authenticate($jwtToken);

            $this->tokenStorage->setToken($authToken);
        } catch (JwtNotFoundException $e) {
            return;
        }
    }
}
