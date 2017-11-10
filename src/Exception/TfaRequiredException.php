<?php

namespace Platformsh\OAuth2\Client\Exception;

/**
 * This exception indicates that two-factor authentication is required.
 *
 * You can ask the user for a two-factor authentication TOTP code, and then
 * retry the request, e.g.:
 *
 * <code>
 *     $provider->getAccessToken(
 *         new \League\OAuth2\Client\Grant\Password(),
 *         [
 *             'username' => 'foo',
 *             'password' => 'bar',
 *             'totp' => 123456,
 *         ]
 *     );
 * </code>
 */
class TfaRequiredException extends \RuntimeException {}
