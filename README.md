Aliro HCE
========

A Host Card Emulation (HCE) implementation of Aliro (a physical access control spec) written in
Kotlin for use with Android.

Overview
--------

This is a library that implements both sides of an Aliro transaction. This is written in pure Kotlin
and is intended to be used from Android, but can easily be used outside of Android if needed.

This is broken down into three main modules:

### `aliro`

This is the core library. This contains most of the classes necessary to act as either a reader or
a user device.

### `aliro-android`

This contains an [Android Keystore][Keystore] implementation of `AliroCrypto` to securely store
the Endpoint and Reader long-term keys.

### `app`

This library includes a sample app in the `app` project with two halves: a reader app and an HCE
Service that functions as a credential (an access card).

Sample App
----------
The sample app contains both halves of an Aliro transaction: the reader app and [an HCE Service][HCE]
that contains an endpoint to function as an access credential. The HCE service is active any time
that the screen is unlocked and the device is not functioning as a reader.

To use, install the app on two devices that have NFC enabled. Choose one device to act as a
user device and the other to act as a reader. On the reader device, open up the sample app
and on the other device, ensure that the screen is on and no NFC readers (especially not the sample
app) are active. Tap the two devices together and you'll get an error!

This error is expected, because the protocol uses mutual authentication. To have a successful
transaction, the user device must know the reader's public key beforehand. To do such,
you must copy the public key from the reader (in a raw format) to the endpoint. As this is a sample
with no formal provisioning system, the value is simply hard-coded into the sample app.

Whenever you launch the reader activity, it'll output its public key in the appropriate format to
logcat:

```
16:20:42.603  D  Reader public key: 041CC26[...]DAB523D
```

In `AliroHCEService.kt` at the very bottom, paste the public key (which should start with `04`) into
the `READER_PUBLIC_KEY` constant:

```Kotlin
class AliroHCEService : HostApduService() {
  // ...
  companion object {
    // ...
    const val READER_PUBLIC_KEY =
      "041CC26[...]DAB523D"
  }
}
```

Then recompile and upload the app to the user device. Now when you tap the two devices together,
the reader should unlock/lock and display the endpoint's public key.

### `AliroHceService` overview

Terminology
-----------

Some clarification of some niche terms that are used in this library.

    * User device - A phone, watch, or other device that holds one or more endpoints.
    * Endpoint - This is container for a public/private key pair that's stored on
                 the user device. A user device can have multiple endpoints. The
                 endpoint's public key is used as the identity of the user with
                 the given reader.
    * Credential - Synonymous with "endpoint".
    * Reader - The device, often mounted near a door or other access-restricted
               resource, that initiates an Aliro transaction and communicates
               with the endpoint. Either the reader or a second device will use
               the endpoint's public key (and any other information it chooses)
               to make a decision about whether to grant the user access to the
               resource.
    * Reader group - A collection of readers that all share the same endpoint on
                     the user device. A common use of reader groups would be a
                     building owned by one company which has multiple readers.

License & Notice
----------------

Notice: This is not an officially supported Google product.

Copyright 2023 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


[Keystore]: https://developer.android.com/training/articles/keystore
[HCE]: https://developer.android.com/guide/topics/connectivity/nfc/hce
