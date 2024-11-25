<?php

namespace Platformsh\OAuth2\Client\Tests\Provider;

use GuzzleHttp\Psr7\Query;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils as Psr7Utils;
use GuzzleHttp\Utils;
use League\OAuth2\Client\Grant\Password;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;
use Platformsh\OAuth2\Client\Grant\ApiToken;
use Platformsh\OAuth2\Client\Provider\Platformsh;
use Platformsh\OAuth2\Client\Tests\MockClient;
use Psr\Http\Message\RequestInterface;

#[CoversClass(Platformsh::class)]
class PlatformshTest extends TestCase
{
    public function testGetAccessTokenWithPassword()
    {
        $mockResponse = function (RequestInterface $request) {
            $requestValues = Query::parse($request->getBody()->getContents());
            if ($requestValues['username'] !== 'foo' || $requestValues['password'] !== 'bar') {
                return (new Response(401))
                    ->withBody(Psr7Utils::streamFor('{"error": "invalid_grant"}'));
            }

            return (new Response(200))
                ->withHeader('Content-Type', 'application/json')
                ->withBody(Psr7Utils::streamFor(Utils::jsonEncode(['access_token' => 123])));
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
            $requestValues = Query::parse($request->getBody()->getContents());
            if ($requestValues['api_token'] !== $apiTokenValue) {
                return (new Response(401))
                    ->withBody(Psr7Utils::streamFor('{
                    "error": "invalid_grant",
                    "error_description": "Invalid API token."
                    }'));
            }

            return (new Response(200))
                ->withHeader('Content-Type', 'application/json')
                ->withBody(Psr7Utils::streamFor(Utils::jsonEncode(['access_token' => 123])));
        };
        $client = MockClient::withResponses([$mockResponse, $mockResponse]);
        $provider = new Platformsh([], ['httpClient' => $client]);
        $grant = new ApiToken();
        $token = $provider->getAccessToken($grant, ['api_token' => 'abcdef']);
        $this->assertEquals(123, $token->getToken());
    }
}
