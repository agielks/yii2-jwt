# Yii2 JWT

This extension provides the [JWT](https://github.com/lcobucci/jwt) integration for the [Yii framework 2.0](http://www.yiiframework.com) (requires PHP 8.0+).
It includes basic HTTP authentication support.

[![Latest Stable Version](http://poser.pugx.org/agielks/yii2-jwt/v)](https://packagist.org/packages/agielks/yii2-jwt) 
[![Total Downloads](http://poser.pugx.org/agielks/yii2-jwt/downloads)](https://packagist.org/packages/agielks/yii2-jwt) 
[![Latest Unstable Version](http://poser.pugx.org/agielks/yii2-jwt/v/unstable)](https://packagist.org/packages/agielks/yii2-jwt) 
[![License](http://poser.pugx.org/agielks/yii2-jwt/license)](https://packagist.org/packages/agielks/yii2-jwt) 
[![PHP Version Require](http://poser.pugx.org/agielks/yii2-jwt/require/php)](https://packagist.org/packages/agielks/yii2-jwt)

## Table of contents

1. [Installation](#installation)
1. [Dependencies](#dependencies)
1. [Basic usage](#basicusage)
   1. [Create token](#basicusage-create)
   1. [Parse token from string](#basicusage-parse)
   1. [Validate token](#basicusage-validate)
1. [Login Example](#login-example)

<a name="installation"></a>
## Instalation

Package is available on [Packagist](https://packagist.org/packages/agielks/yii2-jwt),
you can install it using [Composer](http://getcomposer.org).

```shell
composer require agielks/yii2-jwt ~1.0
```

or add to the require section of your `composer.json` file.

```
"agielks/yii2-jwt": "~1.0"
```

<a name="dependencies"></a>
## Dependencies

- PHP 8.0+
- OpenSSL Extension
- Sodium Extension
- [lcobucci/jwt 4.1](https://github.com/lcobucci/jwt/tree/4.1)

<a name="basic-usage"></i>
## Basic Usage

Add `jwt` component to your configuration file,

```php
'components' => [
    'jwt' => [
        'class' => \agielks\yii2\jwt\Jwt::class,
        // 'singer' => new \Lcobucci\JWT\Signer\Hmac\Sha256(),
        'signer' => 'HS256',
        // 'key' => \Lcobucci\JWT\Signer\Key\InMemory::plainText('my-key'),
        'key' => 'my-key', ,
    ],
],
```

**Important: If you don't provide the signer and the key it will use unsecured signer**

Configure the `authenticator` behavior as follows.

```php
namespace app\controllers;

class SiteController extends \yii\rest\Controller
{
    /**
     * @inheritdoc
     */
    public function behaviors()
    {
        $behaviors = parent::behaviors();
        $behaviors['authenticator'] = [
            'class' => \agielks\yii2\jwt\JwtBearerAuth::class,
        ];

        return $behaviors;
    }
}
```

Also you can use it with `CompositeAuth` reffer to a [doc](http://www.yiiframework.com/doc-2.0/guide-rest-authentication.html).

<a name="basicusage-create"></a>
## Create Token

```php
/* @var $jwt \agielks\yii2\jwt\Jwt */

$now = new DateTimeImmutable();
$jwt = Yii::$app->get('jwt');

$token = $jwt
    ->builder()
    // Configures the issuer (iss claim)
    ->issuedBy('http://example.com')
    // Configures the audience (aud claim)
    ->permittedFor('http://example.org')
    // Configures the id (jti claim)
    ->identifiedBy('62cbfaca6bf7e')
    // Configures the time that the token was issue (iat claim)
    ->issuedAt($now)
    // Configures the time that the token can be used (nbf claim) required for StrictValidAt constraint
    ->canOnlyBeUsedAfter($now)
    // Configures the expiration time of the token (exp claim)
    ->expiresAt($now->modify('+1 hour'))
    // Configures a new claim, called "uid"
    ->withClaim('uid', '62cbfaca6bf7e')
    // Configures a new header, called "foo"
    ->withHeader('foo', 'bar')
    // Builds a new token
    ->getToken($jwt->signer(), $jwt->key());

// Retrieves all headers
$token->headers()->all();

// Retrives typ from headers
$token->headers()->get('typ');

// Print typ from headers
print_r($token->headers()->get('typ'));

// Retrieves all claims
$token->claims()->all();

// Retrieves jti from claims
$token->claims()->get('jti');

// Print jti from claims
print_r($token->claims()->get('jti'));
```

<a name="basicusage-parse"></a>
## Parse Token From String

```php
/* @var $jwt \agielks\yii2\jwt\Jwt */

$now = new DateTimeImmutable();
$jwt = Yii::$app->get('jwt');

$token = $jwt
    ->builder()
    // ...
    ->expiresAt($now->modify('+1 hour'))
    ->getToken($jwt->signer(), $jwt->key())
    ->toString();

// Parse without validation
$data = $jwt->config()->parser()->parse($token);

// Parse with validation
$data = $jwt->load($token);

// Print all headers
print_r($data->headers()->all());

// Print all claims
print_r($data->claims()->all());

// Validate token
var_dump($data->isExpired($now));
var_dump($data->isExpired($now->modify('+2 hour')));
```

<a name="basicusage-validate"></a>
## Validate Token
You can configure your own validation with simple configuration in your component

```php
use \agielks\yii2\jwt\Jwt;
use \Lcobucci\JWT\Signer\Hmac\Sha256;
use \Lcobucci\JWT\Signer\Key\InMemory;
use \Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use \Lcobucci\JWT\Validation\Constraint\SignedWith;
use \Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use \Lcobucci\Clock\SystemClock;

'components' => [
    'jwt' => [
        'class' => Jwt::class,
        'signer' => new Sha256(),
        'key'   => InMemory::plainText('my-key'),
        'constraints' => [
            new LooseValidAt(SystemClock::fromSystemTimezone()),
            new SignedWith(
                new Sha256(),
                InMemory::plainText('my-key')
            ),
            new IdentifiedBy('my-identity'),
        ],
    ],
],
```

<a name="login-example"></a>
## Login Example

### Basic scheme
1. Client send credentials. For example, login + password
2. App validate the credentials
3. If credentials is valid client receive token
4. Client store token for the future requests

### Step by step usage
1. Install component

```shell
composer require agielks/yii2-jwt ~1.0
```

2. Update your components configuration

```php
'components' => [
    // other components here...
    'jwt' => [
        'class' => \agielks\yii2\jwt\Jwt::class,
        // 'singer' => new \Lcobucci\JWT\Signer\Hmac\Sha256(),
        'signer' => 'HS256',
        // 'key' => \Lcobucci\JWT\Signer\Key\InMemory::plainText('my-key'),
        'key' => 'my-key', ,
    ],
    // ...
],
```

3. Change method `User::findIdentityByAccessToken()`

```php
/**
 * {@inheritdoc}
 * @param \Lcobucci\JWT\Token $token
 */
public static function findIdentityByAccessToken($token, $type = null)
{
   return static::findOne(['id' => $token->claims()->get('uid')]);
}
```

If you want to use auth_key as key, update method as follows

```php
/**
 * {@inheritdoc}
 * @param \Lcobucci\JWT\Token $token
 */
public static function findIdentityByAccessToken($token, $type = null)
{
   return static::findOne(['auth_key' => $token->claims()->get('auth_key')]);
}
```

4. Create controller

```php
use agielks\yii2\jwt\JwtBearerAuth;
// Use your own login form
use common\models\LoginForm;
use DateTimeImmutable;
use Yii;
use yii\base\InvalidConfigException;
use yii\filters\Cors;
use yii\rest\Controller;
use yii\web\Response;

/**
 * Class SiteController
 */
class SiteController extends Controller
{
    /**
     * {@inheritdoc}
     */
    public function behaviors()
    {
        $behaviors = parent::behaviors();
        $behaviors['contentNegotiator']['formats']['text/html'] = Response::FORMAT_JSON;
        $behaviors['corsFilter'] = ['class' => Cors::class];
        $behaviors['authenticator'] = [
            'class' => JwtBearerAuth::class,
            'optional' => [
                'login',
            ],
        ];

        return $behaviors;
    }

    /**
     * {@inheritdoc}
     */
    protected function verbs()
    {
        return [
            'login' => ['OPTIONS', 'POST'],
        ];
    }

    /**
     * @return array|LoginForm
     * @throws InvalidConfigException
     */
    public function actionLogin()
    {
        $model = new LoginForm();

        if ($model->load(Yii::$app->getRequest()->getBodyParams(), '') && $model->login()) {
            /* @var $jwt \agielks\yii2\jwt\Jwt */

            $now = new DateTimeImmutable();
            $jwt = Yii::$app->get('jwt');
            $user = $model->getUser();

            return $jwt
                ->builder()
                // Configures the issuer (iss claim)
                ->issuedBy('http://example.com')
                // Configures the audience (aud claim)
                ->permittedFor('http://example.org')
                // Configures the id (jti claim)
                ->identifiedBy($user->id)
                // Configures the time that the token was issue (iat claim)
                ->issuedAt($now)
                // Configures the time that the token can be used (nbf claim)
                ->canOnlyBeUsedAfter($now)
                // Configures the expiration time of the token (exp claim)
                ->expiresAt($now->modify('+1 hour'))
                // Configures a new claim, called "uid"
                ->withClaim('uid', $user->id)
                // Configures a new claim, called "auth_key"
                ->withClaim('auth_key', $user->auth_key)
                // Returns a signed token to be used
                ->getToken($jwt->signer(), $jwt->key())
                // Convert token to string
                ->toString();
        }

        $model->validate();
        return $model;
    }

    /**
     * Test authentication
     */
    public function actionTest()
    {
        return ['auth' => 'success'];
    }
}
```
