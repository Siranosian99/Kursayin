import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:twofish/twofish.dart';

void main() async {
  // Connect to server
  var socket = await Socket.connect('localhost', 12345);

  // Generate RSA key pair
  var random = new Random.secure();
  var key = new RSAKeyGenerator().generate(random, 2048);
  var publicKey = key.publicKey;
  var privateKey = key.privateKey;

  // Send public key to server
  var encodedPublicKey = _encodePublicKey(publicKey);
  socket.add(encodedPublicKey);

  // Receive server's public key and TwoFish key
  var encodedServerPublicKey = await socket.first;
  var serverPublicKey = _decodePublicKey(encodedServerPublicKey);
  var tfKey = await socket.first;

  // Encrypt message using RSA and TwoFish
  var message = 'Hello, server!';
  var messageBytes = utf8.encode(message);
  var rsaCipher = RSAEngine()
    ..init(true, PublicKeyParameter<RSAPublicKey>(serverPublicKey));
  var encryptedRSA = rsaCipher.process(messageBytes);
  var tfCipher = TwoFishCipher(tfKey);
  var encryptedTF = tfCipher.encrypt(encryptedRSA);

  // Send encrypted message to server
  socket.add(encryptedTF);

  // Receive encrypted response from server
  var response = await socket.first;
  var decryptedTF = tfCipher.decrypt(response);
  var decryptedRSA = rsaCipher.process(decryptedTF);
  print(utf8.decode(decryptedRSA)); // Output: Hello, client!
}

Uint8List _encodePublicKey(RSAPublicKey publicKey) {
  var modulus = publicKey.modulus.toRadixString(16);
  var exponent = publicKey.exponent.toRadixString(16);
  var encoded = {
    'modulus': modulus,
    'exponent': exponent,
  };
  var json = jsonEncode(encoded);
  return Uint8List.fromList(utf8.encode(json));
}

RSAPublicKey _decodePublicKey(Uint8List data) {
  var json = utf8.decode(data);
  var encoded = jsonDecode(json);
  var modulus = BigInt.parse(encoded['modulus'], radix: 16);
  var exponent = BigInt.parse(encoded['exponent'], radix: 16);
  return RSAPublicKey(modulus, exponent);
}
