<?php

namespace RemiSan\Silex\JWT\Security\Listener;

use RemiSan\Silex\JWT\Security\JwtAuthenticator;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

class JwtListener implements ListenerInterface
{
    /** @var JwtAuthenticator */
    private $jwtAuthenticator;

    /**
     * JwtListener constructor.
     *
     * @param JwtAuthenticator $jwtAuthenticator
     */
    public function __construct(JwtAuthenticator $jwtAuthenticator)
    {
        $this->jwtAuthenticator = $jwtAuthenticator;
    }

    /**
     * This interface must be implemented by firewall listeners.
     *
     * @param GetResponseEvent $event
     */
    public function handle(GetResponseEvent $event)
    {
        $this->jwtAuthenticator->authenticate($event->getRequest());
    }
}
