<?php

namespace Platformsh\Oauth2;

use GuzzleHttp\ClientInterface;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Grant\RefreshToken;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class GuzzleMiddleware
{
    /** @var \GuzzleHttp\ClientInterface */
    private $client;

    /** @var AbstractProvider $provider */
    private $provider;

    /** @var AbstractGrant $grant */
    private $grant;

    /** @var RefreshToken $refreshGrant */
    private $refreshGrant;

    /** @var \League\OAuth2\Client\Token\AccessToken|null */
    private $accessToken;

    /**
     * GuzzleMiddleware constructor.
     *
     * @param \GuzzleHttp\ClientInterface                     $client
     * @param \League\OAuth2\Client\Provider\AbstractProvider $provider
     * @param \League\OAuth2\Client\Grant\AbstractGrant       $grant
     * @param \League\OAuth2\Client\Grant\RefreshToken|null   $refreshGrant
     */
    public function __construct(ClientInterface $client, AbstractProvider $provider, AbstractGrant $grant, RefreshToken $refreshGrant = null)
    {
        $this->client = $client;
        $this->provider = $provider;
        $this->grant = $grant;
        $this->refreshGrant = $refreshGrant ?: new RefreshToken();
    }

    /**
     * Main middleware callback.
     *
     * @param callable|null $next
     *
     * @return callable
     */
    public function __invoke(callable $next)
    {
        $retries = 0;

        return function (RequestInterface $request, array $options) use ($next, &$retries) {
            if (!$this->isOAuth2($options)) {
                return $next($request, $options);
            }

            $request = $this->authenticateRequest($request);

            return $next($request, $options)
                ->then(function (ResponseInterface $response) use ($request, $options, &$retries) {
                    if ($response->getStatusCode() === 401) {
                        if ($retries++ > 5) {
                            return $response;
                        }

                        $request = $this->authenticateRequest($request);

                        return $this->client->send($request, $options);
                    }

                    return $response;
                });
        };
    }

    /**
     * Check if a request is configured to use OAuth2.
     *
     * @param array $options
     *
     * @return bool
     */
    private function isOAuth2(array $options)
    {
        return isset($options['auth']) && $options['auth'] === 'oauth2';
    }

    /**
     * Add authentication to an HTTP request.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return \Psr\Http\Message\RequestInterface
     */
    private function authenticateRequest(RequestInterface $request)
    {
        if ($this->provider->getBaseAccessTokenUrl([]) === $request->getUri()) {
            return $request;
        }
        $token = $this->getAccessToken(true);
        if ($token !== null) {
            foreach ($this->provider->getHeaders($token->getToken()) as $name => $value) {
                $request = $request->withAddedHeader($name, $value);
            }

            return $request;
        }

        return $request;
    }

    /**
     * Get the current access token.
     *
     * @param bool $acquire Whether to acquire a new token if one doesn't exist.
     *
     * @return \League\OAuth2\Client\Token\AccessToken|null
     *   The Oauth2 access token, or null if no access token is found.
     */
    public function getAccessToken($acquire = false)
    {
        if ($acquire && (!isset($this->accessToken) || $this->accessToken->hasExpired())) {
            $this->accessToken = $this->acquireAccessToken();
        }

        return $this->accessToken;
    }

    /**
     * Acquire a new access token.
     */
    private function acquireAccessToken()
    {
        if (isset($this->accessToken) && !$this->accessToken->hasExpired()) {
            return $this->accessToken;
        }

        if (isset($this->accessToken) && $this->accessToken->getRefreshToken() && $this->accessToken->hasExpired()) {
            return $this->provider->getAccessToken($this->refreshGrant, ['refresh_token' => $this->accessToken->getRefreshToken()]);
        }

        return $this->provider->getAccessToken($this->grant);
    }

    /**
     * Set the access token for the next request.
     *
     * @param \League\OAuth2\Client\Token\AccessToken $token
     */
    public function setAccessToken(AccessToken $token)
    {
        $this->accessToken = $token;
    }
}
