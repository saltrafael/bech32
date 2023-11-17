import 'dart:typed_data';

import '../bech32.dart';

/// An instance of the default implementation of the Bech32MCodec.
const Bech32MCodec bech32m = Bech32MCodec();

class Bech32MCodec extends Bech32Codec {
  const Bech32MCodec();

  @override
  Bech32MDecoder get decoder => Bech32MDecoder();
  @override
  Bech32MEncoder get encoder => Bech32MEncoder();

  @override
  String encode(Bech32 data, [maxLength = Bech32Validations.maxInputLength]) {
    return Bech32MEncoder().convert(data, maxLength);
  }

  @override
  Bech32 decode(String data, [maxLength = Bech32Validations.maxInputLength]) {
    return Bech32MDecoder().convert(data, maxLength);
  }
}

// This class converts a Bech32 class instance to a String.
class Bech32MEncoder extends Bech32Encoder with Bech32MValidations {
  @override
  String convert(Bech32 input, [int maxLength = Bech32Validations.maxInputLength]) {
    var hrp = input.hrp;
    var data = input.data;

    if (hrp.length + data.length + separator.length + Bech32Validations.checksumLength >
        maxLength) {
      throw TooLong(hrp.length + data.length + 1 + Bech32Validations.checksumLength);
    }

    if (hrp.isEmpty) {
      throw TooShortHrp();
    }

    if (hasOutOfRangeHrpCharacters(hrp)) {
      throw OutOfRangeHrpCharacters(hrp);
    }

    if (isMixedCase(hrp)) {
      throw MixedCase(hrp);
    }

    hrp = hrp.toLowerCase();

    // determine chk mod
    var chk = prefixChk(hrp);
    var words = data;

    var result = StringBuffer('${hrp}1');
    for (var i = 0; i < words.length; ++i) {
      final x = words[i];
      if (x >> 5 != 0) throw Exception('Non 5-bit word');

      chk = polymodStep(chk) ^ x;
      result.write(charset[x]);
    }

    for (var i = 0; i < 6; ++i) {
      chk = polymodStep(chk);
    }
    // chk ^= encodingConst == EncodingEnum.bech32 ? 1 : 0x2bc830a3;
    chk ^= 0x2bc830a3;

    for (var i = 0; i < 6; ++i) {
      final v = (chk >> ((5 - i) * 5)) & 0x1f;
      result.write(charset[v]);
    }

    return result.toString();
  }
}

// This class converts a String to a Bech32 class instance.
class Bech32MDecoder extends Bech32Decoder with Bech32MValidations {
  @override
  Bech32 convert(String input, [int maxLength = Bech32Validations.maxInputLength]) {
    if (input.length < 8) throw Exception('$input too short');
    if (input.length > maxLength) throw Exception('Exceeds length limit');

    // don't allow mixed case
    final lowered = input.toLowerCase();
    final uppered = input.toUpperCase();
    if (input != lowered && input != uppered) {
      throw Exception('Mixed-case string $input');
    }
    input = lowered;

    final split = input.lastIndexOf('1');
    if (split == -1) throw Exception('No separator character for $input');
    if (split == 0) throw Exception('Missing prefix for $input');

    final prefix = input.substring(0, split);
    final wordChars = input.substring(split + 1);
    if (wordChars.length < 6) throw Exception('Data too short');

    var chk = prefixChk(prefix);

    final List<int> words = [];
    for (var i = 0; i < wordChars.length; ++i) {
      final c = wordChars[i];
      final v = charset.indexOf(c);
      if (v == -1) throw Exception('Unknown character $c');
      chk = polymodStep(chk) ^ v;

      // not in the checksum?
      if (i + 6 >= wordChars.length) continue;
      words.add(v);
    }

    // if (chk != (encodingConst == EncodingEnum.bech32 ? 1 : 0x2bc830a3)) {
    if (chk != (0x2bc830a3)) {
      throw Exception('Invalid checksum for $input');
    }
    return Bech32(prefix, words);
  }
}

class Bech32MValidations {
  bool isInvalidChecksum(String hrp, List<int> data, List<int> checksum) {
    return !_verifyChecksum(hrp, data + checksum);
  }
}

const constant = 0x2bc830a3;
List<int> _generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

int _polymod(List<int> values) {
  var chk = 1;
  values.forEach((v) {
    var top = chk >> 25;
    chk = (chk & 0x1ffffff) << 5 ^ v;
    for (var i = 0; i < _generator.length; i++) {
      if ((top >> i) & 1 == 1) {
        chk ^= _generator[i];
      }
    }
  });

  return chk;
}

List<int> _hrpExpand(String hrp) {
  var result = hrp.codeUnits.map((c) => c >> 5).toList();
  result = result + [0];

  result = result + hrp.codeUnits.map((c) => c & 31).toList();

  return result;
}

bool _verifyChecksum(String hrp, List<int> dataIncludingChecksum) {
  var values = [..._hrpExpand(hrp), ...dataIncludingChecksum];
  return _polymod([...values, 0, 0, 0, 0, 0, 0]) == constant;
}

/// Polymod Step
int polymodStep(int pre) {
  final b = pre >> 25;
  return ((pre & 0x1ffffff) << 5) ^
      (-((b >> 0) & 1) & 0x3b6a57b2) ^
      (-((b >> 1) & 1) & 0x26508e6d) ^
      (-((b >> 2) & 1) & 0x1ea119fa) ^
      (-((b >> 3) & 1) & 0x3d4233dd) ^
      (-((b >> 4) & 1) & 0x2a1462b3);
}

/// Prefix Check
int prefixChk(String prefix) {
  var chk = 1;
  for (var i = 0; i < prefix.length; ++i) {
    var c = prefix.codeUnitAt(i);
    if (c < 33 || c > 126) throw Exception('Invalid prefix ($prefix)');

    chk = polymodStep(chk) ^ (c >> 5);
  }
  chk = polymodStep(chk);

  for (var i = 0; i < prefix.length; ++i) {
    final v = prefix.codeUnitAt(i);
    chk = polymodStep(chk) ^ (v & 0x1f);
  }
  return chk;
}

/// Bytes to Words
Uint8List toWords(Uint8List bytes) {
  return _convert(data: bytes, inBits: 8, outBits: 5, pad: true);
}

/// Words to Bytes
Uint8List fromWords(Uint8List words) {
  return _convert(data: words, inBits: 5, outBits: 8, pad: false);
}

/// Converter
Uint8List _convert({
  required Uint8List data,
  required int inBits,
  required int outBits,
  required bool pad,
}) {
  var value = 0;
  var bits = 0;
  final maxV = (1 << outBits) - 1;

  final List<int> result = [];
  for (var i = 0; i < data.length; ++i) {
    value = (value << inBits) | data[i];
    bits += inBits;

    while (bits >= outBits) {
      bits -= outBits;
      result.add((value >> bits) & maxV);
    }
  }

  if (pad) {
    if (bits > 0) {
      result.add((value << (outBits - bits)) & maxV);
    }
  } else {
    if (bits >= inBits) throw Exception('Excess padding');
    if (((value << (outBits - bits)) & maxV) != 0) {
      throw Exception('Non-zero padding');
    }
  }

  return Uint8List.fromList(result);
}
