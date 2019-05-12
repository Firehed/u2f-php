<?php
declare(strict_types=1);

namespace Firehed\U2F\CBOR;

use Exception;
use Psr\Log\LoggerInterface;
use OutOfBoundsException;

class Decoder
{
    /** @var LoggerInterface */
    private $logger;

    const MT_UINT = 0;
    const MT_NINT = 1;
    const MT_BYTESTRING = 2;
    const MT_TEXT = 3;
    const MT_ARRAY = 4;
    const MT_MAP = 5;
    const MT_TAG = 6;
    const MT_SIMPLE_AND_FLOAT = 7;

    private const NAME_MAP = [
        'uint',
        'nint',
        'bytestr',
        'textstr',
        'arr',
        'map',
        'tag',
        'fp/simple',
    ];

    private $cbor = '';
    private $i = 0;

    public function __construct()
    {
        $this->logger = new \Firehed\SimpleLogger\Stdout();
    }

    public function decode(string $cbor)
    {
        $this->logger->debug('Starting new decode');
        $this->cbor = $cbor;
        $this->i = 0;
        return $this->decodeItem();
    }

    public function decodeFromByteArray(array $bytes)
    {
        return $this->decode(implode('', array_map('chr', $bytes)));
    }

    public function getNumberOfBytesRead(): int
    {
        return $this->i;
    }

    /**
     * Reads out of the CBOR string and returns the next decoded value
     * @return mixed
     */
    private function decodeItem()
    {
        $item = ord($this->read(1));
        if ($item === 0xff) {
            throw new Stop();
        }
        $majorType = ($item & 0b11100000) >> 5;
        $addtlInfo = ($item & 0b00011111);
        $tn = self::NAME_MAP[$majorType];
        $this->logger->debug("Major type {$majorType} ($tn)");
        switch ($majorType) {
            case self::MT_UINT:
                return $this->decodeUnsignedInteger($addtlInfo);
            case self::MT_NINT:
                return $this->decodeNegativeInteger($addtlInfo);
            case self::MT_BYTESTRING:
                return $this->decodeBinaryString($addtlInfo);
            case self::MT_TEXT:
                return $this->decodeText($addtlInfo);
            case self::MT_ARRAY:
                return $this->decodeArray($addtlInfo);
            case self::MT_MAP:
                return $this->decodeMap($addtlInfo);
            case self::MT_TAG:
                return $this->decodeTag($addtlInfo);
            case self::MT_SIMPLE_AND_FLOAT:
                return $this->decodeSimple($addtlInfo);
            default:
                throw new Exception('Invalid major type');
        }
    }

    private function decodeUnsignedInteger(int $info): int
    {
        if ($info <= 23) {
            $this->logger->debug("uint literal $info");
            return $info;
        }
        if ($info === 24) { // 8-bit int
            $data = ord($this->read(1));
            $this->logger->debug("uint8 $data");
            return $data;
        } elseif ($info === 25) { // 16-bit int
            $data = unpack('n', $this->read(2))[1];
            $this->logger->debug("uint16 $data");
            return $data;
        } elseif ($info === 26) { // 32-bit int
            $data = unpack('N', $this->read(4))[1];
            $this->logger->debug("uint32 $data");
            return $data;
        } elseif ($info === 27) { // 64-bit int
            $data = unpack('J', $this->read(8))[1];
            $this->logger->debug("uint64 $data");
            return $data;
        } else {
            $this->logger->error("DUI {$info}");
            throw new OutOfBoundsException((string)$info);
        }
    }

    private function decodeNegativeInteger(int $addtlInfo): int
    {
        $uint = $this->decodeUnsignedInteger($addtlInfo);
        $negative = -1 - $uint;
        $this->logger->debug("negative int $negative");
        return $negative;
    }

    private function decodeBinaryString(int $addtlInfo): string
    {
        if ($addtlInfo === 31) {
            $ret = '';
            while (true) {
                try {
                    $ret .= $this->decodeItem();
                } catch (Stop $e) {
                    return $ret;
                }
            }
        }
        $length = $this->decodeUnsignedInteger($addtlInfo);
        $str = $this->read($length);
        $this->logger->debug("Bin string ($length) '(omitted)'");
        return $str;
    }

    private function decodeText(int $addtlInfo): string
    {
        if ($addtlInfo === 31) {
            $ret = '';
            while (true) {
                try {
                    $ret .= $this->decodeItem();
                } catch (Stop $e) {
                    return $ret;
                }
            }
        }
        $length = $this->decodeUnsignedInteger($addtlInfo);
        $str = $this->read($length);
        $this->logger->debug("UTF8 string ($length) '$str'");
        return $str;
    }

    private function decodeArray(int $addtlInfo): array
    {
        $ret = [];
        if ($addtlInfo === 31) {
            $this->logger->debug("varlen array");
            while (true) {
                try {
                    $ret[] = $this->decodeItem();
                } catch (Stop $e) {
                    return $ret;
                }
            }
        }
        $numItems = $this->decodeUnsignedInteger($addtlInfo);
        $this->logger->debug("Array of length $numItems");
        for ($i = 0; $i < $numItems; $i++) {
            $this->logger->debug("Getting array #$i");
            $ret[] = $this->decodeItem();
        }
        $this->logger->debug('arr loaded');
        // $this->logger->debug(print_r($ret, true));
        return $ret;
    }

    private function decodeMap(int $addtlInfo): array
    {
        $ret = [];
        if ($addtlInfo === 31) {
            $this->logger->debug("varlen map");
            while (true) {
                try {
                    $key = $this->decodeItem();
                    $ret[$key] = $this->decodeItem();
                } catch (Stop $e) {
                    return $ret;
                }
            }
        }
        $numItems = $this->decodeUnsignedInteger($addtlInfo);
        $this->logger->debug("Map of length $numItems");
        for ($i = 0; $i < $numItems; $i++) {
            $this->logger->debug("Get key $i");
            $key = $this->decodeItem();
            $this->logger->debug("Get value $i");
            $ret[$key] = $this->decodeItem();
            // $this->logger->debug("Map $i {$key}: {$ret[$key]}");
        }
        $this->logger->debug('map loaded');
        // $this->logger->debug(print_r($ret, true));
        return $ret;
    }

    private function decodeTag(int $addtlInfo)
    {
        $this->logger->debug("  ==>  tag $addtlInfo");
        $tag = $this->decodeItem();
        var_dump($tag);
        return $tag;
    }


    private function read(int $numBytes)
    {
        $data = substr($this->cbor, $this->i, $numBytes);
        $this->i += $numBytes;
        return $data;
    }

    private function decodeSimple(int $info)
    {
        switch ($info) {
            case $info <= 19:
                return unassigned;
            case 20:
                return false;
            case 21:
                return true;
            case 22:
                return null;
            case 23:
                return undefined;
            case 24:
                throw new \Exception('idk');
            case 25:
                return $this->readHalfPrecisionFloat();
            case 26:
                return $this->readSinglePrecisionFloat();
            case 27:
                return $this->readDoublePrecisionFloat();
            case 28: case 29: case 30:
                return unassigned;
            case 31:
                return break_code;
        }
    }

    // Adapted from RFC7049 Appendix D
    private function readHalfPrecisionFloat(): float
    {
        $bytes = $this->read(2);
        $half = (ord($bytes[0]) << 8) + ord($bytes[1]);
        $exp = ($half >> 10) & 0x1f;
        $mant = $half & 0x3ff;

        $val = 0;
        if ($exp === 0) {
            $val = self::ldexp($mant, -24);
        } elseif ($exp !== 31) {
            $val = self::ldexp($mant + 1024, $exp - 25);
        } elseif ($mant === 0) {
            $val = \INF;
        } else {
            $val = \NAN;
        }

        return ($half & 0x8000) ? -$val : $val;
    }

    // Adapted from C
    private static function ldexp(float $x, int $exponent): float
    {
        return $x * pow(2, $exponent);
    }

    private function readSinglePrecisionFloat()
    {
        $bytes = $this->read(4);
        $data = unpack('G', $bytes);
        return $data[1];
    }



    private function readDoublePrecisionFloat()
    {
        $bytes = $this->read(8);
        $data = unpack('E', $bytes);
        return $data[1];
    }


}
