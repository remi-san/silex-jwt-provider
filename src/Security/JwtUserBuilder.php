<?php
namespace RemiSan\Silex\JWT\Security;

use Symfony\Component\Security\Core\User\UserInterface;

interface JwtUserBuilder
{
    /**
     * @param string $jwtKey
     *
     * @return void
     */
    public function setJwtKey($jwtKey);

    /**
     * @param string[] $allowedAlgorithms
     *
     * @return void
     */
    public function setAllowedAlgorithms(array $allowedAlgorithms);

    /**
     * @param string $jwtString
     *
     * @return UserInterface
     */
    public function buildUserFromToken($jwtString);
}