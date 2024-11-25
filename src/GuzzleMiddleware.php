<?php

declare(strict_types=1);

namespace Platformsh\OAuth2\Client;

use Closure;
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
    private readonly AbstractProvider $provider;

    private readonly AbstractGrant $grant;

    private readonly array $grantOptions;

    private ?AccessToken $accessToken;

    private ?Closure $tokenSave;

    private ?Closure $onRefreshStart;

    private ?Closure $onRefreshEnd;

    private ?Closure $onRefreshError;

    private ?Closure $onStepUpAuthResponse;

    public function __construct(AbstractProvider $provider, ?AbstractGrant $grant = null, array $grantOptions = [])
    {
        $this->provider = $provider;
        $this->grant = $grant ?: new ClientCredentials();
        $this->grantOptions = $grantOptions;
    }

    /**
     * Main middleware callback.
     */
    public function __invoke(callable $next): callable
    {
        return function (RequestInterface $request, array $options) use ($next) {
            if (! $this->isOAuth2($request, $options)) {
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
                    $this->setAccessToken($newToken);
                } else {
                    // Consider the old token invalid, and get a new one.
                    $this->getAccessToken($token);
                }

                // Retry the request.
                $request = $this->authenticateRequest($request, $this->accessToken);
                return $next($request, $options);
            });
        };
    }

    /**
     * Set a callback that will save a token whenever a new one is acquired.
     *
     * @param callable $tokenSave
     *   A callback accepting one argument (the AccessToken) that will save a
     *   token.
     */
    public function setTokenSaveCallback(callable $tokenSave): void
    {
        $this->tokenSave = Closure::fromCallable($tokenSave);
    }

    /**
     * Sets a callback that will be triggered when token refresh starts.
     *
     * @param callable $callback
     *   A callback which accepts 1 argument, the refresh token being used if
     *   available (a string or null), and returns an AccessToken or null.
     */
    public function setOnRefreshStart(callable $callback): void
    {
        $this->onRefreshStart = Closure::fromCallable($callback);
    }

    /**
     * Set a callback that will be triggered when token refresh ends.
     *
     * @param callable $callback
     *   A callback which accepts 1 argument, the refresh token which was used
     *   if available (a string or null).
     */
    public function setOnRefreshEnd(callable $callback): void
    {
        $this->onRefreshEnd = Closure::fromCallable($callback);
    }

    /**
     * Set a callback that will react to a refresh token error.
     *
     * @param callable $callback
     *   A callback which accepts one argument, the IdentityProviderException, and
     *   returns an AccessToken or null.
     */
    public function setOnRefreshError(callable $callback): void
    {
        $this->onRefreshError = Closure::fromCallable($callback);
    }

    /**
     * Set a callback that will react to a step-up authentication response (RFC 9470).
     *
     * @param callable $callback
     *   A callback which accepts one argument, the response, of type \GuzzleHttp\Message\ResponseInterface,
     *   and returns an AccessToken or null.
     */
    public function setOnStepUpAuthResponse(callable $callback): void
    {
        $this->onStepUpAuthResponse = Closure::fromCallable($callback);
    }

    /**
     * Sets the access token for the next request(s) and saves it to storage.
     */
    public function setAccessToken(AccessToken $token): void
    {
        $this->accessToken = $token;
        if ($this->tokenSave) {
            ($this->tokenSave)($this->accessToken);
        }
    }

    /**
     * Checks for a step-up authentication response (RFC 9470).
     */
    protected function isStepUpAuthenticationResponse(ResponseInterface $response): bool
    {
        $authHeader = implode("\n", $response->getHeader('WWW-Authenticate'));
        return stripos($authHeader, 'Bearer') !== false && str_contains($authHeader, 'insufficient_user_authentication');
    }

    /**
     * Check if a request is configured to use OAuth2.
     */
    private function isOAuth2(RequestInterface $request, array $options): bool
    {
        // The 'auth' option must be set to 'oauth2'.
        if (! isset($options['auth']) || $options['auth'] !== 'oauth2') {
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
     */
    private function authenticateRequest(RequestInterface $request, AccessToken $token): RequestInterface
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
     * @throws IdentityProviderException
     */
    private function getAccessToken(AccessToken $invalid = null): AccessToken
    {
        if (! isset($this->accessToken) || $this->accessToken->hasExpired() || ($invalid && $this->accessToken === $invalid)) {
            $this->setAccessToken($this->acquireAccessToken());
        }

        return $this->accessToken;
    }

    /**
     * Acquire a new access token using a refresh token or the configured grant.
     *
     * @throws IdentityProviderException
     */
    private function acquireAccessToken(): AccessToken
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
                return $this->provider->getAccessToken(new RefreshToken(), [
                    'refresh_token' => $this->accessToken->getRefreshToken(),
                ]);
            } catch (IdentityProviderException $e) {
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
}
