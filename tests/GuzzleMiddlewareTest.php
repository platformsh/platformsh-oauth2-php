<?php

declare(strict_types=1);

namespace Platformsh\OAuth2\Client\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils as Psr7Utils;
use GuzzleHttp\Utils;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Platformsh\OAuth2\Client\GuzzleMiddleware;
use Platformsh\OAuth2\Client\Provider\Platformsh;

#[CoversClass(GuzzleMiddleware::class)]
class GuzzleMiddlewareTest extends TestCase
{
    public static function refreshProvider(): array
    {
        return [
            'refresh' => ['refresh', 'new-access'],
            'token from onRefreshStart' => ['start', 'start-access'],
            'token from onRefreshError' => ['error', 'error-access'],
        ];
    }

    #[DataProvider('refreshProvider')]
    public function testTokenIsSavedBeforeRefreshEnd(string $mode, string $expectedToken)
    {
        $tokenResponse = $mode === 'error'
            ? (new Response(400))
                ->withHeader('Content-Type', 'application/json')
                ->withBody(Psr7Utils::streamFor('{"error": "invalid_grant"}'))
            : (new Response(200))
                ->withHeader('Content-Type', 'application/json')
                ->withBody(Psr7Utils::streamFor(Utils::jsonEncode([
                    'access_token' => 'new-access',
                    'refresh_token' => 'new-refresh',
                    'expires_in' => 3600,
                ])));
        $provider = new Platformsh([], [
            'httpClient' => MockClient::withResponses([$tokenResponse]),
        ]);

        $events = [];
        $middleware = new GuzzleMiddleware($provider);
        $middleware->setTokenSaveCallback(function (AccessToken $token) use (&$events) {
            $events[] = 'save:' . $token->getToken();
        });
        $middleware->setAccessToken(new AccessToken([
            'access_token' => 'old-access',
            'refresh_token' => 'old-refresh',
            'expires' => time() - 60,
        ]));
        $events = [];

        $middleware->setOnRefreshStart(function (?string $refreshToken) use (&$events, $mode) {
            $events[] = 'start:' . $refreshToken;
            if ($mode === 'start') {
                return new AccessToken([
                    'access_token' => 'start-access',
                    'expires_in' => 3600,
                ]);
            }
            return null;
        });
        $middleware->setOnRefreshError(function (IdentityProviderException $e) use (&$events) {
            $events[] = 'error';
            return new AccessToken([
                'access_token' => 'error-access',
                'expires_in' => 3600,
            ]);
        });
        $middleware->setOnRefreshEnd(function (?string $refreshToken) use (&$events) {
            $events[] = 'end:' . $refreshToken;
        });

        $stack = HandlerStack::create(new MockHandler([new Response(200)]));
        $stack->push($middleware);
        $client = new Client([
            'handler' => $stack,
        ]);
        $client->request('GET', 'https://api.example.com/', [
            'auth' => 'oauth2',
        ]);

        $expected = ['start:old-refresh'];
        if ($mode === 'error') {
            $expected[] = 'error';
        }
        $expected[] = 'save:' . $expectedToken;
        $expected[] = 'end:old-refresh';
        $this->assertSame($expected, $events);
    }

    public function testRefreshEndIsCalledOnFailure()
    {
        $provider = new Platformsh([], [
            'httpClient' => MockClient::withResponses([
                (new Response(400))
                    ->withHeader('Content-Type', 'application/json')
                    ->withBody(Psr7Utils::streamFor('{"error": "invalid_grant"}')),
            ]),
        ]);

        $events = [];
        $middleware = new GuzzleMiddleware($provider);
        $middleware->setTokenSaveCallback(function (AccessToken $token) use (&$events) {
            $events[] = 'save:' . $token->getToken();
        });
        $middleware->setAccessToken(new AccessToken([
            'access_token' => 'old-access',
            'refresh_token' => 'old-refresh',
            'expires' => time() - 60,
        ]));
        $events = [];
        $middleware->setOnRefreshEnd(function (?string $refreshToken) use (&$events) {
            $events[] = 'end:' . $refreshToken;
        });

        $stack = HandlerStack::create(new MockHandler([new Response(200)]));
        $stack->push($middleware);
        $client = new Client([
            'handler' => $stack,
        ]);
        try {
            $client->request('GET', 'https://api.example.com/', [
                'auth' => 'oauth2',
            ]);
            $this->fail('Expected an IdentityProviderException');
        } catch (IdentityProviderException) {
        }

        $this->assertSame(['end:old-refresh'], $events);
    }
}
