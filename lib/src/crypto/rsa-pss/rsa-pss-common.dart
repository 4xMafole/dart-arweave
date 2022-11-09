import 'dart:ffi';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/export.dart';

import '../../utils.dart';

Future<Uint8List> rsaPssSign({Uint8List? message, RsaKeyPair? keyPair}) async {
  final pk = await keyPair!.extract();

  final pcPk = RSAPrivateKey(
    decodeBytesToBigInt(pk.n),
    decodeBytesToBigInt(pk.d),
    decodeBytesToBigInt(pk.p),
    decodeBytesToBigInt(pk.q),
    // decodeBytesToBigInt(pk.e),
  );

  final signer = PSSSigner(RSAEngine(), SHA256Digest(), SHA256Digest())
    ..init(
      true,
      ParametersWithSalt(
        PrivateKeyParameter<RSAPrivateKey>(pcPk),
        Uint8List.fromList([]),
      ),
    );
  return signer.generateSignature(message!).bytes;
}

Future<bool> rsaPssVerify({
  Uint8List? input,
  Uint8List? signature,
  BigInt? modulus,
  BigInt? publicExponent,
}) async {
  var signer = PSSSigner(RSAEngine(), SHA256Digest(), SHA256Digest())
    ..init(
      false,
      ParametersWithSalt(
        PublicKeyParameter<RSAPublicKey>(
          RSAPublicKey(
            modulus!,
            publicExponent!,
          ),
        ),
        Uint8List.fromList([]),
      ),
    );

  return signer.verifySignature(input!, PSSSignature(signature!));
}
