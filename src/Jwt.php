<?php

namespace agielks\yii2\jwt;

use Exception;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Throwable;
use yii\base\Component;

/**
 * JSON Web Token implementation, based on this library:
 * https://github.com/lcobucci/jwt
 *
 * @author Agiel K. Saputra <agielkurniawans@gmail.com.com>
 * @since 1.0.0
 */
class Jwt extends Component
{
    /**
     * @var Signer|string $signer The signer
     */
    public $signer;

    /**
     * @var Key|string $key The key
     */
    public $key;
    
    /**
     * @var Encoder $encoder
     */
    public $encoder;

    /**
     * @var Decoder $decoder
     */
    public $decoder;
    
    /**
     * @var Constraint
     */
    public $constraints = [];
    
    /**
     * @var array Supported algorithms
     */
    private $supportedAlgs = [
        'HS256' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
        'HS384' => \Lcobucci\JWT\Signer\Hmac\Sha384::class,
        'HS512' => \Lcobucci\JWT\Signer\Hmac\Sha512::class,
        'ES256' => \Lcobucci\JWT\Signer\Ecdsa\Sha256::class,
        'ES384' => \Lcobucci\JWT\Signer\Ecdsa\Sha384::class,
        'ES512' => \Lcobucci\JWT\Signer\Ecdsa\Sha512::class,
        'RS256' => \Lcobucci\JWT\Signer\Rsa\Sha256::class,
        'RS384' => \Lcobucci\JWT\Signer\Rsa\Sha384::class,
        'RS512' => \Lcobucci\JWT\Signer\Rsa\Sha512::class,
    ];

    /**
     * @var Configuration $config
     */
    private Configuration $config;

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();
        
        if ($this->signer() && $this->key()) {
            $this->config = Configuration::forSymmetricSigner(
                $this->signer(),
                $this->key(),
                $this->encoder(),
                $this->decoder(),
            );
        } else {
            $this->config = Configuration::forUnsecuredSigner($this->encoder(), $this->decoder());
        }
        
        if (!$this->constraints) {
            $this->constraints = [
                new LooseValidAt(SystemClock::fromSystemTimezone()),
                new SignedWith($this->signer(), $this->key())
            ];
        }
    }
    
    /**
     * @see [[Lcobucci\JWT\Builder::__construct()]]
     * @param Encoder|null $encoder
     * @param Decoder|null $encoder
     * @return Builder
     */
    public function builder($claimFormatter = null): Builder
    {
        return $this->config->builder($claimFormatter);
    }
    
    /**
     * @return Configuration
     */
    public function config(): Configuration
    {
        return $this->config;
    }
    
    /**
     * @see [[Lcobucci\JWT\Parser::__construct()]]
     * @param Decoder|null $decoder
     * @param ClaimFactory|null $claimFactory
     * @return Parser
     */
    public function parser(Decoder $decoder = null, ClaimFactory $claimFactory = null): Parser
    {
        return new Parser($decoder, $claimFactory);
    }

    /**
     * @param string $alg
     * @return Signer
     */
    public function signer(): Signer
    {
        if ($this->signer instanceof Signer) {
            return $this->signer;
        }
     
        $class = $this->supportedAlgs[$this->signer] ?? $this->supportedAlgs['HS256'];
        
        if (in_array($this->signer, ['ES256', 'ES384', 'ES512'])) {
            return $class::create();
        }
        
        return new $class();
    }

    /**
     * @param strng $content
     * @param string|null $passphrase
     * @return Key
     */
    public function key(): Key
    {
        if ($this->key instanceof Key) {
            return $this->key;
        }

        if (is_array($this->key)) {
            $contents = $this->key[0] ?? null;
            $passphrase = $this->key[1] ?? '';
            
            return InMemory::plainText($contents, $passphrase);
        }
        
        return InMemory::plainText($this->key);
    }
    
    /**
     * @return Encoder
     */
    public function encoder()
    {
        return $this->encoder;
    }
    
    /**
     * @return Decoder
     */
    public function decoder()
    {
        return $this->decoder;
    }

    /**
     * Parses the JWT and returns a token class
     * @param string $token JWT
     * @param bool $validate
     * @param bool $verify
     * @return Token|null
     * @throws Throwable
     */
    public function load($token)
    {
        $config = $this->config;
        
        try {
            $data = $config->parser()->parse($token);

            if (!$config->validator()->validate($data, ...$this->constraints)) {
                return null;
            }
            
            return $data;
        } catch (Exception $e) {
            return null;
        }
    }
}
