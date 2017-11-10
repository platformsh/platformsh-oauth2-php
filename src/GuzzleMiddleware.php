<?php

namespace Platformsh\OAuth2\Client;

use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Grant\ClientCredentials;
use League\OAuth2\Client\Grant\RefreshToken;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class GuzzleMiddleware
{
    /** @var AbstractProvider $provider */
    private $provider;

    /** @var AbstractGrant $grant */
    private $grant;

    /** @var \League\OAuth2\Client\Token\AccessToken|null */
    private $accessToken;

    /** @var array */
    private $grantOptions = [];

    /** @var callable|null */
    private $tokenSave;

    /**
     * GuzzleMiddleware constructor.
     *
     * @param \League\OAuth2\Client\Provider\AbstractProvider $provider
     * @param \League\OAuth2\Client\Grant\AbstractGrant       $grant
     * @param array                                           $grantOptions
     */
    public function __construct(AbstractProvider $provider, AbstractGrant $grant = null, array $grantOptions = [])
    {
        $this->provider = $provider;
        $this->grant = $grant ?: new ClientCredentials();
        $this->grantOptions = $grantOptions;
    }

    /**
     * Set a callback that will save a token whenever a new one is acquired.
     *
     * @param callable $tokenSave
     *   A callback accepting one argument (the AccessToken) that will save a
     *   token.
     */
    public function setTokenSaveCallback(callable $tokenSave)
    {
        $this->tokenSave = $tokenSave;
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
        return function (RequestInterface $request, array $options) use ($next, &$retries) {
            if (!$this->isOAuth2($options)) {
                return $next($request, $options);
            }

            $token = $this->getAccessToken();
            if ($token && $this->provider->getBaseAccessTokenUrl([]) !== $request->getUri()) {
                $request = $this->authenticateRequest($request, $token);
            }

            /** @var \GuzzleHttp\Promise\PromiseInterface $promise */
            $promise = $next($request, $options);

            return $promise->then(
                function (ResponseInterface $response) use ($request, $options, &$token, $next) {
                    if ($response->getStatusCode() === 401) {
                        // Consider the old token invalid, and get a new one.
                        $token = $this->getAccessToken($token);
                        $request = $this->authenticateRequest($request, $token);
                        $response = $next($request, $options);
                    }

                    return $response;
                }
            );
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
     * @param \Psr\Http\Message\RequestInterface      $request
     * @param \League\OAuth2\Client\Token\AccessToken $token
     *
     * @return \Psr\Http\Message\RequestInterface
     */
    private function authenticateRequest(RequestInterface $request, AccessToken $token)
    {
        foreach ($this->provider->getHeaders($token->getToken()) as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        return $request;
    }

    /**
     * Get the current access token.
     *
     * @param AccessToken|null $invalid
     *   A token to consider invalid.
     *
     * @return \League\OAuth2\Client\Token\AccessToken|null
     *   The Oauth2 access token, or null if no access token is found.
     */
    private function getAccessToken(AccessToken $invalid = null)
    {
        if (!isset($this->accessToken) || $this->accessToken->hasExpired() || ($invalid && $this->accessToken === $invalid)) {
            $this->accessToken = $this->acquireAccessToken();
            if ($this->accessToken !== null && is_callable($this->tokenSave)) {
                $callback = $this->tokenSave;
                $callback($this->accessToken);
            }
        }

        return $this->accessToken;
    }

    /**
     * Acquire a new access token.
     */
    private function acquireAccessToken()
    {
        if (isset($this->accessToken) && $this->accessToken->getRefreshToken()) {
            return $this->provider->getAccessToken(new RefreshToken(), ['refresh_token' => $this->accessToken->getRefreshToken()]);
        }

        return $this->provider->getAccessToken($this->grant, $this->grantOptions);
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
