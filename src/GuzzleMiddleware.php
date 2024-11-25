<?php

namespace Platformsh\OAuth2\Client;

use GuzzleHttp\Exception\BadResponseException;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Grant\ClientCredentials;
use League\OAuth2\Client\Grant\RefreshToken;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class GuzzleMiddleware
{
    /** @var AbstractProvider $provider */
    private $provider;

    /** @var AbstractGrant $grant */
    private $grant;

    /** @var AccessToken|null */
    private $accessToken;

    /** @var array */
    private $grantOptions;

    /** @var callable|null */
    private $tokenSave;

    /** @var callable|null */
    protected $onRefreshStart;

    /** @var callable|null */
    protected $onRefreshEnd;

    /** @var callable|null */
    protected $onRefreshError;

    /** @var callable|null */
    protected $onStepUpAuthResponse;

    /**
     * GuzzleMiddleware constructor.
     *
     * @param AbstractProvider $provider
     * @param AbstractGrant $grant
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
     * Sets a callback that will be triggered when token refresh starts.
     *
     * @param callable $callback
     *   A callback which accepts 1 argument, the refresh token being used if
     *   available (a string or null), and returns an AccessToken or null.
     */
    public function setOnRefreshStart(callable $callback)
    {
        $this->onRefreshStart = $callback;
    }

    /**
     * Set a callback that will be triggered when token refresh ends.
     *
     * @param callable $callback
     *   A callback which accepts 1 argument, the refresh token which was used
     *   if available (a string or null).
     */
    public function setOnRefreshEnd(callable $callback)
    {
        $this->onRefreshEnd = $callback;
    }

    /**
     * Set a callback that will react to a refresh token error.
     *
     * @param callable $callback
     *   A callback which accepts one argument, the BadResponseException, and
     *   returns an AccessToken or null.
     */
    public function setOnRefreshError(callable $callback)
    {
        $this->onRefreshError = $callback;
    }

    /**
     * Set a callback that will react to a step-up authentication response (RFC 9470).
     *
     * @param callable $callback
     *   A callback which accepts one argument, the response, of type \GuzzleHttp\Message\ResponseInterface,
     *   and returns an AccessToken or null.
     */
    public function setOnStepUpAuthResponse(callable $callback)
    {
        $this->onStepUpAuthResponse = $callback;
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

            return $promise->then(function (ResponseInterface $response) use ($request, $options, $token, $next) {
                if ($response->getStatusCode() !== 401) {
                    return $response;
                }

                if (isset($this->onStepUpAuthResponse) && $this->isStepUpAuthenticationResponse($response)) {
                    $newToken = call_user_func($this->onStepUpAuthResponse, $response);
                    $this->accessToken = $newToken;
                    if (is_callable($this->tokenSave)) {
                        call_user_func($this->tokenSave, $this->accessToken);
                    }
                } else {
                    // Consider the old token invalid, and get a new one.
                    $this->getAccessToken($token);
                }

                // Retry the request.
                $request = $this->authenticateRequest($request, $token);
                return $next($request, $options);
            });
        };
    }

    /**
     * Checks for a step-up authentication response (RFC 9470).
     *
     * @param ResponseInterface $response
     *
     * @return bool
     */
    protected function isStepUpAuthenticationResponse(ResponseInterface $response)
    {
        $authHeader = implode("\n", $response->getHeader('WWW-Authenticate'));
        return stripos($authHeader, 'Bearer') !== false && strpos($authHeader, 'insufficient_user_authentication') !== false;
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
     * @param RequestInterface $request
     * @param AccessToken $token
     *
     * @return RequestInterface
     */
    private function authenticateRequest(RequestInterface $request, AccessToken $token)
    {
        foreach ($this->provider->getHeaders($token->getToken()) as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        return $request;
    }

    /**
     * Get the current or a new access token.
     *
     * @param AccessToken|null $invalid
     *   A token to consider invalid.
     *
     * @return AccessToken
     *   The OAuth2 access token.
     * @throws IdentityProviderException
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
     * @throws IdentityProviderException
     */
    private function acquireAccessToken()
    {
        if (isset($this->accessToken) && $this->accessToken->getRefreshToken()) {
            $currentRefreshToken = $this->accessToken->getRefreshToken();
            try {
                if (isset($this->onRefreshStart)) {
                    $result = call_user_func($this->onRefreshStart, $currentRefreshToken);
                    if ($result instanceof AccessToken) {
                        return $result;
                    }
                }
                return $this->provider->getAccessToken(new RefreshToken(), ['refresh_token' => $this->accessToken->getRefreshToken()]);
            } catch (BadResponseException $e) {
                if (isset($this->onRefreshError)) {
                    $accessToken = call_user_func($this->onRefreshError, $e);
                    if ($accessToken) {
                        return $accessToken;
                    }
                }
                throw $e;
            } finally {
                if (isset($this->onRefreshEnd)) {
                    call_user_func($this->onRefreshEnd, $currentRefreshToken);
                }
            }
        }

        return $this->provider->getAccessToken($this->grant, $this->grantOptions);
    }

    /**
     * Set the access token for the next request(s).
     *
     * @param AccessToken $token
     */
    public function setAccessToken(AccessToken $token)
    {
        $this->accessToken = $token;
    }

    /**
     * Set the access token for the next request(s), and save it to storage.
     *
     * @param AccessToken $token
     */
    public function saveAccessToken(AccessToken $token)
    {
        $this->accessToken = $token;
        if (is_callable($this->tokenSave)) {
            call_user_func($this->tokenSave, $this->accessToken);
        }
    }
}
