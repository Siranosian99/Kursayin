import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:twofish/twofish.dart';

void main() async {
  // Generate RSA key pair
  var random = new Random.secure();
  var key = new RSAKeyGenerator().generate(random, 2048);
  var publicKey = key.publicKey;
  var privateKey = key.privateKey;

  // Generate TwoFish key
  var tfKey = generateRandomBytes(32); // 256-bit key

  // Wait for client connection
  var serverSocket = await ServerSocket.bind('localhost', 12345);
  var clientSocket = await serverSocket.first;

  // Receive public key from client
  var encodedClientPublicKey = await clientSocket.first;
  var clientPublicKey = _decodePublicKey(encodedClientPublicKey);

  // Send public key and TwoFish key to client
  var encodedPublicKey = _encodePublicKey(publicKey);
  clientSocket.add(encodedPublicKey);
  clientSocket.add(tfKey);

  // Receive encrypted message from client
  var encrypted = await clientSocket.first;
  var tfCipher = TwoFishCipher(tfKey);
  var decrypted = tfCipher.decrypt(encrypted);
  print(utf8.decode(decrypted)); // Output: Hello, server!

  // Send encrypted response to client
  var response = 'Hello, client!';
  var responseBytes = utf8.encode(response);
  var encryptedResponse = tfCipher.encrypt(responseBytes);
  clientSocket.add(encryptedResponse);
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
