<?php
declare(strict_types=1);

namespace Firehed\U2F\CBOR;

use RuntimeException;

/**
 * This is a clunky workaround for not being able to (nicely) return a sum type
 * indicating it's time to stop during decoding.
 */
class Stop extends RuntimeException
{
}
