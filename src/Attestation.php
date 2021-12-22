<?php

declare(strict_types=1);

namespace Firehed\U2F;

/**
 * @internal
 * https://www.w3.org/TR/webauthn-2/#sctn-attestation-types (6.5.3)
 */
class Attestation
{
    const TYPE_BASIC = 'Basic';
    const TYPE_SELF = 'Self';
    const TYPE_ATT_CA = 'AttCA';
    const TYPE_ANON_CA = 'AnonCA';
    const TYPE_NONE = 'None';

    /** @var self::TYPE_* */
    private $type;

    /* Array of certificates? */
    private $trustPath;
}
