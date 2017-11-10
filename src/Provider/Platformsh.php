<?php

namespace Platformsh\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Platformsh\OAuth2\Client\Exception\TfaRequiredException;
use Psr\Http\Message\ResponseInterface;

class Platformsh extends AbstractProvider
{
    use BearerAuthorizationTrait;

    const TFA_HEADER = 'X-Drupal-TFA';

    /** @var \Psr\Http\Message\UriInterface */
    private $baseUri;

    /**
     * Provider constructor.
     *
     * @param array $options
     * @param array $collaborators
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        $options += ['base_uri' => 'https://accounts.platform.sh'];
        $this->baseUri = \GuzzleHttp\Psr7\uri_for($options['base_uri']);

        parent::__construct($options, $collaborators);
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->baseUri->withPath('/oauth2/authorize')->__toString();
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->baseUri->withPath('/oauth2/token')->__toString();
    }

    /**
     * {@inheritdoc}
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return $this->baseUri->withPath('/oauth2/userinfo')->__toString();
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultScopes()
    {
        return ['account'];
    }

    /**
     * {@inheritdoc}
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (!empty($data['error'])) {
            if ($this->requiresTfa($response)) {
                throw new TfaRequiredException($data['error_description']);
            }
            throw new IdentityProviderException($data['error_description'], 0, $data);
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new GenericResourceOwner($response, 'id');
    }

    /**
     * {@inheritdoc}
     *
     * The option 'totp' can be provided for two-factor authentication.
     */
    public function getAccessToken($grant, array $options = [])
    {
        $grant = $this->verifyGrant($grant);

        $params = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
        ];

        $params = $grant->prepareRequestParameters($params, $options);

        // Modify the request for TFA (two-factor authentication) support.
        $request = $this->getAccessTokenRequest($params);
        if ($grant->__toString() === 'password' && isset($options['totp'])) {
            $request = $request->withHeader(self::TFA_HEADER, $options['totp']);
        }

        $response = $this->getParsedResponse($request);
        $prepared = $this->prepareAccessTokenResponse($response);

        return $this->createAccessToken($prepared, $grant);
    }

    /**
     * Check whether the response requires two-factor authentication.
     *
     * @param \Psr\Http\Message\ResponseInterface $response
     *
     * @return bool
     */
    private function requiresTfa(ResponseInterface $response)
    {
        return substr($response->getStatusCode(), 0, 1) === '4' && $response->hasHeader(self::TFA_HEADER);
    }

    /**
     * {@inheritdoc}
     */
    protected function getAllowedClientOptions(array $options)
    {
        return ['timeout', 'proxy', 'base_uri', 'verify', 'debug'];
    }
}
