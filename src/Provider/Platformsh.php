<?php

namespace Platformsh\OAuth2\Client\Provider;

use GuzzleHttp\Psr7\Utils;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Platformsh extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /** @var string */
    private $tokenUrl;

    /** @var string */
    private $authorizeUrl;

    /** @var string */
    private $apiUrl;

    /**
     * Provider constructor.
     *
     * @param array $options
     * @param array $collaborators
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        if (empty($options['token_url'])) {
            if (!empty($options['base_uri'])) {
                $options['token_url'] = Utils::uriFor($options['base_uri'])
                    ->withPath('/oauth2/token')
                    ->__toString();
            } else {
                $options['token_url'] = 'https://auth.api.platform.sh/oauth2/token';
            }
        }
        if (empty($options['authorize_url'])) {
            $options['authorize_url'] = Utils::uriFor($options['token_url'])
                ->withPath('/oauth2/authorize')
                ->__toString();
        }
        if (empty($options['api_url'])) {
            $options['api_url'] = 'https://api.platform.sh';
        }
        $this->tokenUrl = $options['token_url'];
        $this->authorizeUrl = $options['authorize_url'];
        $this->apiUrl = $options['api_url'];

        parent::__construct($options, $collaborators);
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->authorizeUrl;
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->tokenUrl;
    }

    /**
     * {@inheritdoc}
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return Utils::uriFor($this->apiUrl)
            ->withPath('/users/me')
            ->__toString();
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultScopes()
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (!empty($data['error'])) {
            $message = !empty($data['error_description']) ? $data['error_description'] : $data['error'];
            throw new IdentityProviderException($message, 0, $data);
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new GenericResourceOwner($response, $response['id']);
    }

    /**
     * {@inheritdoc}
     */
    protected function getAllowedClientOptions(array $options)
    {
        return [
            'timeout',
            'proxy',
            'base_uri',
            'verify',
            'debug',
            'api_url',
            'token_url',
            'authorize_url',
        ];
    }
}
