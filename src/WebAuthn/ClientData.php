<?php
declare(strict_types=1);

namespace Firehed\U2F\WebAuthn;

use Firehed\U2F\ChallengeTrait;
use Firehed\U2F\ClientDataInterface;

use function Firehed\U2F\fromBase64Web;
use function hash;
use function json_decode;
use function parse_url;

class ClientData implements ClientDataInterface
{
    use ChallengeTrait;

    private $json;
    private $decoded;

    private function __construct()
    {
    }

    public static function fromJson(string $json): ClientData
    {
        $wacd = new self;
        $wacd->json = $json;

        $wacd->decoded = json_decode($json, true, 512, \JSON_THROW_ON_ERROR);
        $wacd->setChallenge(fromBase64Web($wacd->decoded['challenge']));
        return $wacd;
    }

    public function getApplicationParameter(): string
    {
        $origin = $this->decoded['origin'];
        // TODO: you can go to a higher level domain in a valid way
        $host = parse_url($origin, PHP_URL_HOST);

        return hash('sha256', $host, true);
    }

    public function getChallengeParameter(): string
    {
        return hash('sha256', $this->json, true);
    }

    public function jsonSerialize()
    {
        return json_decode($this->json, true);
    }
}
