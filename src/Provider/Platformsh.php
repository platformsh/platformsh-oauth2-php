<?php

namespace Platformsh\Oauth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Platformsh\Oauth2\Client\Grant\PasswordWithTfa;
use Psr\Http\Message\ResponseInterface;

class Platformsh extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * {@inheritdoc}
     */
    public function getBaseAuthorizationUrl()
    {
        return 'https://accounts.platform.sh/oauth2/authorize';
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return 'https://accounts.platform.sh/oauth2/token';
    }

    /**
     * {@inheritdoc}
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return 'https://accounts.platform.sh/oauth2/userinfo';
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
            throw new IdentityProviderException($data['error'], 1, $data);
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
        if ($grant instanceof PasswordWithTfa) {
            $request = $grant->modifyRequest($request);
        }

        $response = $this->getParsedResponse($request);
        $prepared = $this->prepareAccessTokenResponse($response);

        return $this->createAccessToken($prepared, $grant);
    }
}
