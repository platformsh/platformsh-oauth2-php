<?php

declare(strict_types=1);

namespace Platformsh\OAuth2\Client\Grant;

use League\OAuth2\Client\Grant\AbstractGrant;

class ApiToken extends AbstractGrant
{
    protected function getName(): string
    {
        return 'api_token';
    }

    protected function getRequiredRequestParameters(): array
    {
        return ['api_token'];
    }
}
