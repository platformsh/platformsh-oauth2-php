<?php

namespace Platformsh\OAuth2\Client\Grant;

use League\OAuth2\Client\Grant\AbstractGrant;

class ApiToken extends AbstractGrant
{
    /**
     * {@inheritdoc}
     */
    protected function getName()
    {
        return 'api_token';
    }

    /**
     * {@inheritdoc}
     */
    protected function getRequiredRequestParameters()
    {
        return ['api_token'];
    }
}
