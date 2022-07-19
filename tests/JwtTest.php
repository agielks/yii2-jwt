<?php

namespace agielks\yii2\jwt\tests;

use agielks\yii2\jwt\Jwt;
use DateTimeImmutable;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use PHPUnit\Framework\TestCase;
use Yii;

class JwtTest extends TestCase
{
    /**
     * Secret key
     */
    public const SECRET = 'secret';

    /**
     * Issuer
     */
    public const ISSUER = 'http://example.com';

    /**
     * Audience
     */
    public const AUDIENCE = 'http://example.org';

    /**
     * Id
     */
    public const ID = '62cbfaca6bf7e';

    /**
     * @var Jwt
     */
    public $jwt;

    /**
     * @ineritdoc
     */
    public function setUp(): void
    {
        $this->jwt = Yii::createObject(Jwt::class, [[
            'signer' => 'HS256',
            'key' => self::SECRET,
        ]]);
    }

    /**
     * @return Token created token
     */
    public function createToken()
    {
        $now   = new DateTimeImmutable();

        return $this
            ->jwt
            ->builder()
            // Configures the issuer (iss claim)
            ->issuedBy(self::ISSUER)
            // Configures the audience (aud claim)
            ->permittedFor(self::AUDIENCE)
            // Configures the id (jti claim)
            ->identifiedBy(self::ID)
            // Configures the subject
            ->relatedTo(self::ID)
            // Configures the time that the token was issue (iat claim)
            ->issuedAt($now)
            // Configures the time that the token can be used (nbf claim)
            ->canOnlyBeUsedAfter($now)
            // Configures the expiration time of the token (exp claim)
            ->expiresAt($now->modify('+1 hour'))
            // Configures a new claim, called "uid"
            ->withClaim('uid', self::ID)
            // Configures a new header, called "foo"
            ->withHeader('foo', 'bar')
            // Builds a new token
            ->getToken($this->jwt->signer(), $this->jwt->key());
    }

    /**
     * Validate Algorithms
     */
    public function testAlgorithms()
    {
        $algs = [
            'HS256', 'HS384', 'HS512',
            'ES256', 'ES384', 'ES512',
            'RS256', 'RS384', 'RS512',
            new \Lcobucci\JWT\Signer\Hmac\Sha256(),
        ];

        foreach ($algs as $alg) {
            $component = Yii::createObject(Jwt::class, [[
                'signer' => $alg,
                'key' => InMemory::plainText(self::SECRET),
            ]]);

            $this->assertTrue($component instanceof Jwt);
        }
    }

    /**
     * Validate Keys
     */
    public function testKeys()
    {
        $keys = [
            self::SECRET,
            InMemory::plainText(self::SECRET),
            [self::SECRET, self::SECRET],
        ];

        foreach ($keys as $key) {
            $component = Yii::createObject(Jwt::class, [[
                'signer' => 'HS256',
                'key' => $key,
            ]]);

            $this->assertTrue($component instanceof Jwt);
        }
    }

    public function testHeaders()
    {
        $token = $this->createToken();

        $expected = [
            'typ' => 'JWT',
            'alg' => 'HS256',
            'foo' => 'bar',
        ];
        $actual = $token->headers()->all();

        $this->assertEquals($expected, $actual);
    }

    public function testClaims()
    {
        $token = $this->createToken();

        $expected = [
            'iss' => 'http://example.com',
            'aud' => [
                'http://example.org'
            ],
            'jti' => '62cbfaca6bf7e',
            'iat' => $token->claims()->get('iat'),
            'nbf' => $token->claims()->get('nbf'),
            'exp' => $token->claims()->get('exp'),
            'uid' => '62cbfaca6bf7e',
            'sub' => '62cbfaca6bf7e',
        ];

        $actual = $token->claims()->all();
        $this->assertEquals($expected, $actual);
    }

    /**
     * Test HasBeenIssuedBefore
     */
    public function testHasBeenIssuedBefore()
    {
        $token = $this->createToken();
        $this->assertTrue($token->hasBeenIssuedBefore(new DateTimeImmutable()));
    }

    /**
     * Test HasBeenIssuedBy
     */
    public function testHasBeenIssuedBy()
    {
        $token = $this->createToken();
        $this->assertTrue($token->hasBeenIssuedBy(self::ISSUER));
    }

    /**
     * Test IsExpired
     */
    public function testIsExpired()
    {
        $token = $this->createToken();
        $this->assertFalse($token->isExpired(new DateTimeImmutable()));
    }

    /**
     * Test IdentifiedBy
     */
    public function testIdentifiedBy()
    {
        $token = $this->createToken();
        $this->assertTrue($token->isIdentifiedBy(self::ID));
    }

    /**
     * Test IsMinimumTimeBefore
     */
    public function testIsMinimumTimeBefore()
    {
        $token = $this->createToken();
        $this->assertTrue($token->isMinimumTimeBefore(new DateTimeImmutable()));
    }

    /**
     * Test IsPermittedFor
     */
    public function testIsPermittedFor()
    {
        $token = $this->createToken();
        $this->assertTrue($token->isPermittedFor(self::AUDIENCE));
    }

    /**
     * Test IsRelatedTo
     */
    public function testIsRelatedTo()
    {
        $token = $this->createToken();
        $this->assertTrue($token->isRelatedTo(self::ID));
    }

    /**
     * Test Playload
     */
    public function testPlayload()
    {
        $token = $this->createToken();
        $this->assertEquals($token->headers()->toString() . '.' . $token->claims()->toString(), $token->payload());
    }

    /**
     * Validate IdentifiedBy
     */
    public function testValidateIdentifiedBy()
    {
        $token = $this->createToken();

        $true = $this->jwt->config()->validator()->validate($token, new IdentifiedBy(self::ID));
        $false = $this->jwt->config()->validator()->validate($token, new IdentifiedBy(uniqid()));

        $this->assertTrue($true);
        $this->assertFalse($false);
    }

    /**
     * Validate IssuedBy
     */
    public function testValidateIssuedBy()
    {
        $token = $this->createToken();

        $true = $this->jwt->config()->validator()->validate($token, new IssuedBy(self::ISSUER));
        $false = $this->jwt->config()->validator()->validate($token, new IssuedBy(self::AUDIENCE));

        $this->assertTrue($true);
        $this->assertFalse($false);
    }

    /**
     * Validate LooseValidAt
     */
    public function testValidateLooseValidAt()
    {
        $token = $this->createToken();

        $true = $this->jwt->config()
            ->validator()
            ->validate($token, new LooseValidAt(SystemClock::fromSystemTimezone()));

        $this->assertTrue($true);
    }

    /**
     * Validate PermittedFor
     */
    public function testValidatePermittedFor()
    {
        $token = $this->createToken();

        $true = $this->jwt->config()->validator()->validate($token, new PermittedFor(self::AUDIENCE));
        $false = $this->jwt->config()->validator()->validate($token, new PermittedFor(self::ISSUER));

        $this->assertTrue($true);
        $this->assertFalse($false);
    }

    /**
     * Validate SignedWith
     */
    public function testValidateSignedWith()
    {
        $token = $this->createToken();

        $true = $this->jwt->config()
            ->validator()
            ->validate($token, new SignedWith($this->jwt->signer(), $this->jwt->key()));

        $this->assertTrue($true);
    }

    /**
     * Validate StrictValidAt
     */
    public function testValidateStrictValidAt()
    {
        $token = $this->createToken();

        $true = $this->jwt->config()
            ->validator()
            ->validate($token, new StrictValidAt(SystemClock::fromSystemTimezone()));

        $this->assertTrue($true);
    }

    /**
     * Validate InvalidToken
     */
    public function testValidateInvalidToken()
    {
        $token = 'jwt' . $this->createToken()->toString();
        $null = $this->jwt->load($token);
        $this->assertNull($null);
    }

    /**
     * Validate ExpiredToken
     */
    public function testValidateLoadToken()
    {
        $token = $this->jwt->load('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImZvbyI6ImJhciJ9.eyJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vZXhhbXBsZS5vcmciLCJqdGkiOiI2MmNiZmFjYTZiZjdlIiwiaWF0IjoxNjU3NjA4Nzg0LjE3MzAzOSwibmJmIjoxNjU3NjA4Nzg0LjE3MzAzOSwiZXhwIjoxNjU3NjA4ODQ0LjE3MzAzOSwidWlkIjoiNjJjYmZhY2E2YmY3ZSJ9.pe4vmCs2DtOR8uipN0P-3byjTC4bTyRi0ibs61bpDXM');
        $this->assertFalse($token instanceof UnencryptedToken);
    }
}
