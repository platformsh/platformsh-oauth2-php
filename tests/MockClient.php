<?php

namespace Platformsh\OAuth2\Client\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;

class MockClient
{
    /**
     * Creates a Guzzle client with these mock responses.
     *
     * @param array $responses An array of PSR-7 ResponseInterface responses,
     *                         callables, Exceptions, or Promises.
     *
     * @return Client
     */
    public static function withResponses(array $responses = [])
    {
        return new Client([
            'handler' => HandlerStack::create(new MockHandler($responses)),
        ]);
    }
}
