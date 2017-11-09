<?php

namespace Platformsh\OAuth2\Client\Grant;

use League\OAuth2\Client\Grant\Password;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class PasswordWithTfa extends Password
{
    const TFA_HEADER = 'X-Drupal-TFA';

    /** @var int|string|null */
    private $otp;

    /**
     * Modify a request to send the time-based OTP in the header.
     *
     * @param RequestInterface $request
     *
     * @return RequestInterface
     */
    public function modifyRequest(RequestInterface $request)
    {
        if (isset($this->otp)) {
            if ($request->getUri()->getScheme() !== 'https') {
                throw new \BadMethodCallException('Cannot add OTP token to non-HTTPS request.');
            }

            $request = $request->withHeader(self::TFA_HEADER, $this->otp);
        }

        return $request;
    }

    /**
     * Set the time-based OTP code for the next request.
     *
     * @param int|string $otp
     */
    public function setOtp($otp)
    {
        $this->otp = $otp;
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
