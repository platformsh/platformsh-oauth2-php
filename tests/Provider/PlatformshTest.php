<?php

namespace Platformsh\OAuth2\Client\Tests\Provider;

use function GuzzleHttp\json_encode;
use function GuzzleHttp\Psr7\parse_query;
use GuzzleHttp\Psr7\Response;
use function GuzzleHttp\Psr7\stream_for;
use League\OAuth2\Client\Grant\Password;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Platformsh\OAuth2\Client\Grant\ApiToken;
use Platformsh\OAuth2\Client\Provider\Platformsh;
use Platformsh\OAuth2\Client\Tests\MockClient;
use Psr\Http\Message\RequestInterface;

class PlatformshTest extends \PHPUnit_Framework_TestCase
{

    public function testGetAccessTokenWithPassword()
    {
        $mockResponse = function (RequestInterface $request) {
            $requestValues = parse_query($request->getBody()->getContents());
            if ($requestValues['username'] !== 'foo' || $requestValues['password'] !== 'bar') {
                return (new Response(401))
                    ->withBody(stream_for('{"error": "invalid_grant"}'));
            }

            return (new Response(200))
                ->withHeader('Content-Type', 'application/json')
                ->withBody(stream_for(json_encode(['access_token' => 123])));
        };
        $client = MockClient::withResponses([$mockResponse, $mockResponse]);
        $provider = new Platformsh([], ['httpClient' => $client]);
        $grant = new Password();
        $token = $provider->getAccessToken($grant, [
            'username' => 'foo',
            'password' => 'bar',
        ]);
        $this->assertEquals(123, $token->getToken());
        $this->expectException(IdentityProviderException::class);
        $provider->getAccessToken($grant, [
            'username' => 'foo',
            'password' => 'bar2',
        ]);
    }

    public function testGetAccessTokenWithApiToken()
    {
        $apiTokenValue = 'abcdef';
        $mockResponse = function (RequestInterface $request) use ($apiTokenValue) {
            $requestValues = parse_query($request->getBody()->getContents());
            if ($requestValues['api_token'] !== $apiTokenValue) {
                return (new Response(401))
                    ->withBody(stream_for('{
                    "error": "invalid_grant",
                    "error_description": "Invalid API token."
                    }'));
            }

            return (new Response(200))
                ->withHeader('Content-Type', 'application/json')
                ->withBody(stream_for(json_encode(['access_token' => 123])));
        };
        $client = MockClient::withResponses([$mockResponse, $mockResponse]);
        $provider = new Platformsh([], ['httpClient' => $client]);
        $grant = new ApiToken();
        $token = $provider->getAccessToken($grant, ['api_token' => 'abcdef']);
        $this->assertEquals(123, $token->getToken());
    }
}
