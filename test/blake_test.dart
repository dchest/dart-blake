#import("dart:crypto");
#import("dart:utf");

//TODO(dchest) figure out how to get path to Dart SDK.
#import("/Users/dchest/sources/dart/dart-sdk/lib/unittest/unittest.dart");

#import("../blake.dart");

main() {
  test("BLAKE256", () {
    var zeroes = [];
    zeroes.insertRange(0, 72, 0);
    
    var vectors = [
      ["7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7",
      "The quick brown fox jumps over the lazy dog"],
      
      ["07663e00cf96fbc136cf7b1ee099c95346ba3920893d18cc8851f22ee2e36aa6",
      "BLAKE"],
      
      ["716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a",
      ""],
      
      ["18a393b4e62b1887a2edf79a5c5a5464daf5bbb976f4007bea16a73e4c1e198e",
      "'BLAKE wins SHA-3! Hooray!!!' (I have time machine)"],
      
      ["fd7282ecc105ef201bb94663fc413db1b7696414682090015f17e309b835f1c2",
      "Go"],
      
      ["1e75db2a709081f853c2229b65fd1558540aa5e7bd17b04b9a4b31989effa711",
      "HELP! I'm trapped in hash!"],
      
      ["4181475cb0c22d58ae847e368e91b4669ea2d84bcd55dbf01fe24bae6571dd08",
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congue ligula ac quam viverra nec consectetur ante hendrerit. Donec et mollis dolor. Praesent et diam eget libero egestas mattis sit amet vitae augue. Nam tincidunt congue enim, ut porta lorem lacinia consectetur. Donec ut libero sed arcu vehicula ultricies a non tortor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ut gravida lorem. Ut turpis felis, pulvinar a semper sed, adipiscing id dolor. Pellentesque auctor nisi id magna consequat sagittis. Curabitur dapibus enim sit amet elit pharetra tincidunt feugiat nisl imperdiet. Ut convallis libero in urna ultrices accumsan. Donec sed odio eros. Donec viverra mi quis quam pulvinar at malesuada arcu rhoncus. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. In rutrum accumsan ultricies. Mauris vitae nisi at sem facilisis semper ac in est."],
      
      // requires one padding byte
      ["af95fffc7768821b1e08866a2f9f66916762bfc9d71c4acb5fd515f31fd6785a",
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congu"],
  
      ["0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87",
       "\x00"],
       
      ["d419bad32d504fb7d44d460c42c5593fe544fa4c135dec31e21bd9abdcc22d41",
       new String.fromCharCodes(zeroes)],
    ];
     
    vectors.forEach((v) {
      var h = new BLAKE256();
      h.update(encodeUtf8(v[1]));
      expect(CryptoUtils.bytesToHex(h.digest()), v[0]);
    });
  });
}