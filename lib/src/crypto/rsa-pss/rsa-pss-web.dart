import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../../utils.dart';
import '../crypto.dart';
import 'rsa-pss-common.dart' as common;

final rsaPss = RsaPss(sha256, nonceLengthInBytes: 0);

Future<Uint8List> rsaPssSign(
    {required Uint8List message, required RsaKeyPair keyPair}) async {
  try {
    final signature = await rsaPss.sign(message, keyPair: keyPair);
    return Uint8List.fromList(signature.bytes);
  } catch (err) {
    if (err is UnimplementedError) {
      return common.rsaPssSign(message: message, keyPair: keyPair);
    } else {
      rethrow;
    }
  }
}

Future<bool> rsaPssVerify({
  required Uint8List input,
  required Uint8List signature,
  required BigInt modulus,
  required BigInt publicExponent,
}) async {
  try {
    final valid = await rsaPss.verify(
      input,
      signature: Signature(
        signature,
        publicKey: RsaPublicKey(
          n: encodeBigIntToBytes(modulus),
          e: encodeBigIntToBytes(publicExponent),
        ),
      ),
    );

    return valid;
  } catch (err) {
    if (err is UnimplementedError) {
      return common.rsaPssVerify(
        input: input,
        signature: signature,
        modulus: modulus,
        publicExponent: publicExponent,
      );
    } else {
      rethrow;
    }
  }
}
