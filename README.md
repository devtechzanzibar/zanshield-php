# ZanShield SDK for PHP

Add ZanShield multi-factor authentication to your system's login. Your system checks the password; ZanShield handles the second factor, deciding whether the user sets up a first method or verifies an existing one. This package builds the ticket you send and checks the acknowledgement you get back.

## Install

```bash
composer require zanshield/sdk
```

Requires PHP 8.1+ and [phpseclib3](https://phpseclib.com/), installed automatically. phpseclib is used because PHP's native OAEP padding is fixed to SHA-1.

## Usage

```php
use ZanShield\Sdk\AcknowledgementRejectedException;
use ZanShield\Sdk\ZanShieldClient;

$client = new ZanShieldClient(
    'PAYROLL01',
    'EGAZ',
    ZanShieldClient::loadPrivateKey(file_get_contents('/secure/zanshield-private.pem')),
    ZanShieldClient::loadPublicKey(file_get_contents('/secure/zanshield-engine-public.pem')),
    $txnIdStore, // see below
);

// 1. After the user's password is correct. fullName and mobile are optional (null);
//    without a mobile number the user can't choose SMS codes.
$ticket = $client->createTicket($user->id, $user->email, $user->fullName, $user->phone);
header('Location: ' . ZanShieldClient::portalUrl('https://portal.zanshield.devtech.co.tz', $ticket));

// 2. At your redirect URI:
try {
    $ack = $client->acceptAcknowledgement($_GET['ticket']);
    startSessionFor($ack->userId);
} catch (AcknowledgementRejectedException $e) {
    // Genuine, but must not sign in: $e->reason is NOT_AUTHENTICATED, EXPIRED or REPLAYED.
}
```

`acceptAcknowledgement` checks the signature, a successful verification (`responseCode` 9000), freshness (3 minutes by default; set it in the constructor), and that the `txnID` hasn't been used before.

**Pass a shared `TxnIdStore`.** PHP normally starts a new process per request, so the in-memory default can't remember anything between requests. Implement `TxnIdStore::markUsed()` over your database, for example a table with a unique `txn_id` column, or over APCu or Redis.

## License

Apache-2.0
