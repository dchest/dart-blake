import "dart:crypto";
import "../blake.dart";

final MEGABYTE = 1024*1024;

measure(name, fn) {
  var stopWatch = new Stopwatch()..start();
  var bytes = fn();
  print("${name} ${stopWatch.elapsedInMs()/1000}s per ${bytes/MEGABYTE} MB");
}

main() {
  print("Running...");
  
  var zeroes = [];
  zeroes.insertRange(0, 5*MEGABYTE, 0);
  
  measure("BLAKE-256", () {
    var blake = new BLAKE256();
    blake.update(zeroes);
    blake.digest();
    return zeroes.length;
  });
  
  measure("SHA-256", () {
    var sha = new SHA256();
    sha.update(zeroes);
    sha.digest();
    return zeroes.length;
  });
}