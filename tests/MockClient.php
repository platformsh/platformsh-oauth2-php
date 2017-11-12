<?php

namespace Platformsh\OAuth2\Client\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;

class MockClient extends Client
{

    /**
     * Create a Guzzle client with these mock responses.
     *
     * @param \Psr\Http\Message\ResponseInterface[] $responses
     *
     * @return \GuzzleHttp\Client
     */
    public static function withResponses(array $responses = [])
    {
        $config['handler'] = HandlerStack::create(new MockHandler($responses));

        return new static($config);
    }

}
