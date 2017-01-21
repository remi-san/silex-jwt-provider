<?php

namespace RemiSan\Silex\JWT\ServiceProvider;

use Assert\Assertion;
use RemiSan\Silex\JWT\Security\AuthenticationProvider\JwtAuthenticationProvider;
use RemiSan\Silex\JWT\Security\EntryPoint\JwtAuthenticationEntryPoint;
use RemiSan\Silex\JWT\Security\JwtAuthenticator;
use RemiSan\Silex\JWT\Security\JwtUserBuilder;
use RemiSan\Silex\JWT\Security\Listener\JwtListener;
use RemiSan\Silex\JWT\Security\RetrievalStrategy\GuzzleRequestRetrievalStrategy;
use Pimple\Container;
use Pimple\ServiceProviderInterface;

class JwtServiceProvider implements ServiceProviderInterface
{
    /**
     * Registers services on the given app.
     *
     * This method should only be used to configure services and parameters.
     * It should not get services.
     *
     * @param Container $app
     */
    public function register(Container $app)
    {
        $app['security.jwt_retrieval.strategy'] = function () use ($app) {
            return new GuzzleRequestRetrievalStrategy();
        };
        
        $app['security.entry_point.jwt._proto'] = $app->protect(
            function () use ($app) {
                return function () {
                    return new JwtAuthenticationEntryPoint();
                };
            }
        );

        $app['security.jwt.authenticator'] = function () use ($app) {
            return new JwtAuthenticator(
                $app['security.token_storage'],
                $app['security.authentication_manager'],
                $app['security.jwt_retrieval.strategy']
            );
        };
        
        $app['security.authentication_listener.factory.jwt'] = $app->protect(
            function ($name, $options) use ($app) {
                $app['security.authentication_provider.' . $name . '.jwt'] = function () use ($app, $options) {

                    Assertion::subclassOf($options['user_builder_class'], JwtUserBuilder::class);
                    /** @var JwtUserBuilder $userBuilder */
                    $userBuilder = new $options['user_builder_class']();
                    $userBuilder->setJwtKey($options['secret_key']);
                    $userBuilder->setAllowedAlgorithms($options['allowed_algorithms']);

                    return new JwtAuthenticationProvider($userBuilder);
                };
                
                $app['security.authentication_listener.' . $name . '.jwt'] = function () use ($app, $name, $options) {
                    return new JwtListener($app['security.jwt.authenticator']);
                };
                
                $app['security.entry_point.' . $name . '.jwt'] = $app['security.entry_point.jwt._proto'](
                    $name,
                    $options
                );
                
                return array(
                    'security.authentication_provider.' . $name . '.jwt',
                    'security.authentication_listener.' . $name . '.jwt',
                    'security.entry_point.' . $name . '.jwt',
                    'pre_auth',
                );
            }
        );
    }
}
