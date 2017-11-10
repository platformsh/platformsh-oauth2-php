<?php

namespace Platformsh\OAuth2\Client\Grant;

use League\OAuth2\Client\Grant\Password;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class PasswordWithTfa extends Password
{
    const TFA_HEADER = 'X-Drupal-TFA';

    /**
     * Modify a request to send the time-based OTP in the header.
     *
     * @param RequestInterface $request
     * @param int|string       $totp
     *
     * @return RequestInterface
     */
    public function addTotp(RequestInterface $request, $totp)
    {
        if ($request->getUri()->getScheme() !== 'https') {
            throw new \BadMethodCallException('Cannot add TOTP token to non-HTTPS request.');
        }

        $request = $request->withHeader(self::TFA_HEADER, $totp);

        return $request;
    }

    /**
     * Check whether the response requires a time-based OTP code.
     *
     * @param \Psr\Http\Message\ResponseInterface $response
     *
     * @return bool
     */
    public static function requiresOtp(ResponseInterface $response)
    {
        return substr($response->getStatusCode(), 0, 1) === '4' && $response->hasHeader(self::TFA_HEADER);
    }
}
