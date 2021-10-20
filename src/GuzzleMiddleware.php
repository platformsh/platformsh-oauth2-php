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
     * @param callable $next
     *
     * @return callable
     */
    public function __invoke(callable $next)
    {
        return function (RequestInterface $request, array $options) use ($next) {
            if (!$this->isOAuth2($request, $options)) {
                return $next($request, $options);
            }

            $token = $this->getAccessToken();
            $request = $this->authenticateRequest($request, $token);

            /** @var \GuzzleHttp\Promise\PromiseInterface $promise */
            $promise = $next($request, $options);

            return $promise->then(
                function (ResponseInterface $response) use ($request, $options, $token, $next) {
                    if ($response->getStatusCode() === 401) {
                        // Consider the old token invalid, and get a new one.
                        $token = $this->getAccessToken($token);

                        // Retry the request.
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
     * @param RequestInterface $request
     * @param array            $options
     *
     * @return bool
     */
    private function isOAuth2(RequestInterface $request, array $options)
    {
        // The 'auth' option must be set to 'oauth2'.
        if (!isset($options['auth']) || $options['auth'] !== 'oauth2') {
            return false;
        }

        // The request must be not for an access token endpoint.
        if ($this->provider->getBaseAccessTokenUrl([]) === $request->getUri()->__toString()) {
            return false;
        }

        return true;
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
     * @return \League\OAuth2\Client\Token\AccessToken
     *   The OAuth2 access token.
     */
    private function getAccessToken(AccessToken $invalid = null)
    {
        if (!isset($this->accessToken) || $this->accessToken->hasExpired() || ($invalid && $this->accessToken === $invalid)) {
            $this->accessToken = $this->acquireAccessToken();
            if (is_callable($this->tokenSave)) {
                call_user_func($this->tokenSave, $this->accessToken);
            }
        }

        return $this->accessToken;
    }

    /**
     * Acquire a new access token using a refresh token or the configured grant.
     *
     * @return AccessToken
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
