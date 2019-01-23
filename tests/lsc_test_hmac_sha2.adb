-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2018 Componolit GmbH
-- All rights reserved.
--
-- Redistribution  and  use  in  source  and  binary  forms,  with  or  without
-- modification, are permitted provided that the following conditions are met:
--
--    * Redistributions of source code must retain the above copyright notice,
--      this list of conditions and the following disclaimer.
--
--    * Redistributions in binary form must reproduce the above copyright
--      notice, this list of conditions and the following disclaimer in the
--      documentation and/or other materials provided with the distribution.
--
--    * Neither the name of the  nor the names of its contributors may be used
--      to endorse or promote products derived from this software without
--      specific prior written permission.
--
-- THIS SOFTWARE IS PROVIDED BY THE  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-- AND ANY  EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT LIMITED  TO, THE
-- IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
-- ARE  DISCLAIMED. IN  NO EVENT  SHALL  THE COPYRIGHT  HOLDER OR  CONTRIBUTORS
-- BE  LIABLE FOR  ANY  DIRECT, INDIRECT,  INCIDENTAL,  SPECIAL, EXEMPLARY,  OR
-- CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT  LIMITED  TO,  PROCUREMENT  OF
-- SUBSTITUTE GOODS  OR SERVICES; LOSS  OF USE,  DATA, OR PROFITS;  OR BUSINESS
-- INTERRUPTION)  HOWEVER CAUSED  AND ON  ANY THEORY  OF LIABILITY,  WHETHER IN
-- CONTRACT,  STRICT LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE OR  OTHERWISE)
-- ARISING IN ANY WAY  OUT OF THE USE OF THIS SOFTWARE, EVEN  IF ADVISED OF THE
-- POSSIBILITY OF SUCH DAMAGE.
-------------------------------------------------------------------------------

with AUnit.Assertions; use AUnit.Assertions;
with Util; use Util;
with LSC.SHA2.HMAC;
with LSC.Types;
with Ada.Text_IO; use Ada.Text_IO;

use LSC;

package body LSC_Test_HMAC_SHA2 is

   procedure Test_HMAC (Algo    : LSC.SHA2.Algorithm_Type;
                        Key     : String;
                        Msg     : String;
                        Mac     : String;
                        Textkey : Boolean := False;
                        Textmsg : Boolean := False)
   is
      use type LSC.Types.Bytes;

      Converted_Key : LSC.Types.Bytes := (if Textkey then T2B (Key) else S2B (Key));
      Converted_Msg : LSC.Types.Bytes := (if Textmsg then T2B (Msg) else S2B (Msg));
      Converted_Mac : LSC.Types.Bytes := S2B (Mac);

      Result : LSC.Types.Bytes :=
         LSC.SHA2.HMAC.HMAC (Algorithm => Algo,
                             Key       => Converted_Key,
                             Message   => Converted_Msg,
                             Length    => Converted_Mac'Length);
   begin
      Assert (Result = Converted_Mac, "Invalid HMAC: got " & B2S (Result) & ", expected " & Mac);
   end Test_HMAC;

   ---------------------------------------------------------------------------

   procedure Test_HMAC_SHA256 (Key     : String;
                               Msg     : String;
                               Mac     : String;
                               Textkey : Boolean := False;
                               Textmsg : Boolean := False)
   is
   begin
      Test_HMAC (LSC.SHA2.SHA256, Key, Msg, Mac, Textkey, Textmsg);
   end Test_HMAC_SHA256;

   ---------------------------------------------------------------------------

   procedure Test_HMAC_SHA384 (Key     : String;
                               Msg     : String;
                               Mac     : String;
                               Textkey : Boolean := False;
                               Textmsg : Boolean := False)
   is
   begin
      Test_HMAC (LSC.SHA2.SHA384, Key, Msg, Mac, Textkey, Textmsg);
   end Test_HMAC_SHA384;

   ---------------------------------------------------------------------------
   -- RFC 4868 PRF Test vectors
   ---------------------------------------------------------------------------

   procedure Test_HMAC_SHA256_Prf (T : in out Test_Cases.Test_Case'Class)
   is
   begin
      --  PRF-1
      Test_HMAC_SHA256 ("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                        "Hi There",
                        "b0344c61d8db38535ca8afceaf0bf12b 881dc200c9833da726e9376c2e32cff7",
                        Textmsg => True);
      --  PRF-2
      Test_HMAC_SHA256 ("Jefe",
                        "what do ya want for nothing?",
                        "5bdcc146bf60754e6a042426089575c7 5a003f089d2739839dec58b964ec3843",
                        Textkey => True, Textmsg => True);
      --  PRF-3
      Test_HMAC_SHA256 ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaa",
                        "dddddddddddddddddddddddddddddddd dddddddddddddddddddddddddddddddd" &
                        "dddddddddddddddddddddddddddddddd dddd",
                        "773ea91e36800e46854db8ebd09181a7 2959098b3ef8c122d9635514ced565fe");
      --  PRF-4
      Test_HMAC_SHA256 ("0102030405060708090a0b0c0d0e0f10 111213141516171819",
                        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" &
                        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcd",
                        "82558a389a443c0ea4cc819899f2083a 85f0faa3e578f8077a2e3ff46729665b");
      --  PRF-5
      Test_HMAC_SHA256 ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                        "aaaaaa",
                        "54657374205573696e67204c61726765 72205468616e20426c6f636b2d53697a" &
                        "65204b6579202d2048617368204b6579 204669727374",
                        "60e431591ee0b67f0d8a26aacbf5b77f 8e0bc6213728c5140546040f0ee37f54");
   end Test_HMAC_SHA256_Prf;

   ---------------------------------------------------------------------------
   -- RFC 4868 AUTH Test vectors
   ---------------------------------------------------------------------------

   procedure Test_HMAC_SHA256_Auth (T : in out Test_Cases.Test_Case'Class)
   is
   begin
      --  AUTH256-1
      Test_HMAC_SHA256 ("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "Hi There", "198a607eb44bfbc69903a0f1cf2bbdc5", Textmsg => True);
      --  AUTH256-2
      Test_HMAC_SHA256 ("JefeJefeJefeJefeJefeJefeJefeJefe", "what do ya want for nothing?", "167f928588c5cc2eef8e3093caa0e87c", Textkey => True, Textmsg => True);
      --  AUTH256-3
      Test_HMAC_SHA256 ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" &
                        "dddddddddddddddddddddddddddddddddddd",
                        "cdcb1220d1ecccea91e53aba3092f962");
      --  AUTH256-4
      Test_HMAC_SHA256 ("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" &
                        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                        "372efcf9b40b35c2115b1346903d2ef4");
   end Test_HMAC_SHA256_Auth;

   ---------------------------------------------------------------------------
   -- NIST test vectors are from
   --    CAVP Testing: Keyed-Hash Message Authentication Code (HMAC)
   --    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip
   ---------------------------------------------------------------------------

   procedure Test_HMAC_SHA256_NIST (T : in out Test_Cases.Test_Case'Class)
   is
   begin
      Test_HMAC_SHA256
        (Key => "6f35628d65813435534b5d67fbdb54cb33403d04e843103e6399f806cb5df95febbdd61236f33245",
         Msg => "752cff52e4b90768558e5369e75d97c69643509a5e5904e0a386cbe4d0970ef73f918f675945a9aefe26daea27587e8dc909dd56fd0468805f834039b345f855cfe19c44b55af241fff3ffcd8045cd5c288e6c4e284c3720570b58e4d47b8feeedc52fd1401f698a209fccfa3b4c0d9a797b046a2759f82a54c41ccd7b5f592b",
         Mac => "05d1243e6465ed9620c9aec1c351a186");
      Test_HMAC_SHA256
        (Key => "17b52858e3e135be4440d7df0ca996f41ccb78b7d8cc1924d830fe81e0fd279c131ce3546303e95a",
         Msg => "e0eff00f3c46e96c8d5bd181283e4605348e3fa10b47945de3dcc159ae86e7bd3fdb13f2ada2c313fce6a69efa49a470689b1ef05aab778ae15dd35fe6fd1e3a59d351c68cf8f0ffd968d7e78b57377afcc9dce3fa5db1f06f6985c4414c0fcc780030f49fef791a6c08edc2a311080c373f00e4b2044a79d82860f0871bc259",
         Mac => "c4061427764f979468ac422891dea9ca");
      Test_HMAC_SHA256
        (Key => "7c67410e0a9e3d7ae4f3d04eff1c2716891e821c6ec1dc822142ce8d9949b1449a1a033a350f0ba8",
         Msg => "bfd166793abdcffbbd56df769150d1466c18a67af452c7e67f86ed741d163ebbd874b9d33a91d3671099620b6eddbbd0f31117164eb73ca201db59f1650131cbef5c7b1bb14089fd24da2919241fc9303c02def424ea861d88636bb90b13ebc38cf177f8a8b139e68082fa46bcfc428bd054c1bb7dd3ed7e9b86ed751736b6cc",
         Mac => "1a0d427e79a7bdca7b11579339d0ff77");
      Test_HMAC_SHA256
        (Key => "b2c450128d0744421c3f31fab37bbcdfb5a2ff2fb706d1f7e23c4886992c7d215c648ff8edb2eb59",
         Msg => "f6989ebb07aadaeef970f0b5ceb806ecffe77cc20f3c221a6659a9315dff5881961900e68efc320075edafd83de320c6f18f0892489af6d97a2effb252b76b9284ebaf6d42089c1e0a5cd509c20b86ff060d5362c1768f89fafaaf65f1b0fe656b1692984a567e1260c7499085b79f5fe7684779a25855f291c5a192637177c4",
         Mac => "f0d7c63677033ada0b502a4e95b20e43");
      Test_HMAC_SHA256
        (Key => "a7744321d73938b8eea13754909029881bbd727439fe2731b1c67b7083eb7b5d33adfcca65f5d189",
         Msg => "71299ca3daff2331082db370bdf8ceec227b71bdc49c3b14dc3fd213d3ba83e2058828ffc6414fd5a2c99891e9c85f316c5b9bdd810a067b4df97f7e4262acfee642e30ed6534b4a0b3b3eaf5d03f2b045ca5985e7bb45c7503cd03afc68fbea9bc09579141d5fb7cbea6d73208fcf913830715dff98401f6d708ef009b5b8cb",
         Mac => "f6302c5fd7c8495e233b5d6129f361da");
      Test_HMAC_SHA256
        (Key => "795a0ba9b02984cfce5e7395fb94d98fcf12ae5db8a06e239c9ad439bf42e523e65a31c3bdf356cd",
         Msg => "8b4aa20de6c1f051d11ad50ba2e4fc4ff1ec478455f9b5b96fb9893d2afca969402044c101ccb73c50e2b2dfeeae9690fb64222ab9c94fcd943078785fa8bed9e174ab6390bb16a29c8146cb2fd65a98f44de752d6b0e42f0af2c3df4f65e162742d201c1bf5d22bbee1daf8efc30d0ce491df2632173b8ad9e9b29b819cd8ac",
         Mac => "fbecae19c2ce766d286c8ce70133b669");
      Test_HMAC_SHA256
        (Key => "aa41b5222efdea882cbebd11d343000ec2ff6b2f7bbfa746158ea54f32d534ae31c7d3b7a5fcc373",
         Msg => "3274a0326682ba59d6c47db4164e3e9937bfad4199c6507101e5305aeb75d2bf22eb68558d59496f4c389fda04645f0676687f6757fc631b5bcc98cd947bc4d9fae8ddb14bb09a7f15f4270c105c1de0b25bb1abfeb52ce39d3f9baf2fe6c704e3f3670d458e95d158807f10e53d5f6d1221add336fa9211ecc7a1c767bfc286",
         Mac => "cec1ed7aa0f1cbd6b7f667a079a88577");
      Test_HMAC_SHA256
        (Key => "aaa449923f0cd3e6a7e74d9c56a7eb6a3b4c3dea97e6a8400e5517fcff54ee4211b640280eee415f",
         Msg => "0486d2647e2cdf7bba36c8f3ff9e2941001c706eb1a44cbd582f638ee7be4482899c9ce07be4ac381d44fa4649004718e33ac273b1707b746d461a731986d12c93658f216908773aee4690af8eb0be275ecef122f7ac9c94859569d21b1f2bb24a6813eef19e28ca56c5f1f776b474b69a6165412b5f9766c7a5b6759491385c",
         Mac => "ae73b3740a7a8a07223635faaef0ba71");
      Test_HMAC_SHA256
        (Key => "6c13d74ed004ee92adb44b755be92e8440434704a1c22790b788f50406e0629aea80de53730b0d99",
         Msg => "fd5cf72ee0779aab7daa27d5c8a8d31f4082ba47741e7e73c6e631806fbd7597c337e101b609a73ca0be744e3dac9859f827677069f4dfa91c008b739452a62a8f3f84e98cdd2ea08bba4d6614cd49107aacb1026100de457e36d3da9e78684eeadca88f69db77fec60478c554f12d6b4f7b60a6652ac27074efd35c9616012b",
         Mac => "4304f9864598f801c6aa1a692aabb8be");
      Test_HMAC_SHA256
        (Key => "12541d81c6958221c44a958ecd7f48c08a89a8687d306c2f3814c93ecd498e0485456c33d5fc950c",
         Msg => "31f51d395a06885efc34032349bc635cd4b1004ceafcb1c426a2f88b4045790226eeb1084e09e41c4ab157c19d2ec027cdbcfb07b98efecf2d130fffb47835d3ad6eec22a12d1c86d4b94cbd1a64134fec94d071bbc69b2a84d37cb4a572da25efff364ffc7b19e4c3d34ade6965451d5bc0e95299ab711d556aa572bc3c5141",
         Mac => "edad94e7c30813be7c5ac58df418d8a8");
      Test_HMAC_SHA256
        (Key => "a1e8cf95c6d729507661fcc687156922c8975645e5f36eba8a3069eccb298e96c498767c7c741259",
         Msg => "48bdae9d81f1beaccfd00374f522f90cfedd8e3dd93be13947104a89f75b9a48ee1ba48f2d64fc308eb1fea7f07c124d930c2fcfc58f9edfbf680129caca9389a686b17b2b219ad3312a73aeaeca8ea81e9deb4f28c0ffd87e2cb5110542b39736a6de49c45120fc7ee269717835f3846537cba548f98d8c4c036e29efea80da",
         Mac => "d78d7d266cf83add4355e7395b63adfd");
      Test_HMAC_SHA256
        (Key => "c7e5ede152c50a935e76b59979e08638a09cfffd01ac7008056a18ab8ebf8d347e955e06788ff6ef",
         Msg => "1e1bdaa984ca68730faf61c697d5fb15955b28992d69bae86c68cbc9ce735c4703083c04f2042cd0ffce407a89d288e6b731f06075b66530b90d396f0b2fc91944215d6396de4f4ecc92707cd308a7427a66db00761813ada90adcb6a41aec096acd046c76401b140062b8737d61a0516562b11e38750e87c3c87c47a01b0c40",
         Mac => "b7de3be2fae6ab41aa6386b8460223c6");
      Test_HMAC_SHA256
        (Key => "6ab37be64f4b1e032c5a43dc03e4afb65c6ab1329fbca9c4c10fc766224f158eb6b7b85d649e7319",
         Msg => "490700ea587a001c7162f0946f7ca6a5e3655c6e09ba4c13fa7e7d4e22bcdc27f56d8effde9b85d378c751bf018939c10c768bc0754630cd9a3783a8c8ac6486f41a8711ac2412b14d05680a752f3fc6bb31f9949ede3170bcac9426455af211aed69429aa5dd13d56e4dc7cb3b7e03a5a604ff16bca7786c7a656ce7f0eaf51",
         Mac => "380eaf65a9be83322508498748504b50");
      Test_HMAC_SHA256
        (Key => "785a1189381824a8131e885ba4b23c2e94e3dfdc03652cc32a9cc1963ff72452997f077315b0cb67",
         Msg => "5bc93a655f35d346f9e96e96e9bb560178dad04ea46259917d2d30a2cfed14cd01774fcb3d62f3f1d2d164a8d68d161d0f57983a147cd2d4afa98b2686012e7efa6dcd36503366e60ecb65d8a8ee6bbc5cef4e9d5b4e6114298bf5bc46381fe50e52bc8dded1b38c787e7a0ea905dc46294bf961c2018eb9b47a764c59b9716c",
         Mac => "b452d180b9cacc10cb012f48dd19e4cd");
      Test_HMAC_SHA256
        (Key => "394575dded531000e776ae4adc64c4affb5b220ac5a96ebf1f72d19fa6aef00c42711e5dfe6fcf84",
         Msg => "b733d51a7eaa4b6bb0e378a218caa6ae7475a3f32909184d34d7165264cbf2d8c60753b861cb89d12498204f1d95b52dec3109f8760a54d6de0edcc8b1dfc52c607c2b86f41f6e7ffd61cd2ecba43797e1b25d71a7a20c2d5ffcba335a1d5f6f6cdc860c9d6da37f2186a7c88bc1d2f43d42c8e72399e858a1e9d91dc94a65a9",
         Mac => "3f6417a99d7186bc36e6d0d61467360d");
      Test_HMAC_SHA256
        (Key => "14d45ca2a3d4977dab2b7d442c6f9e57ce348e0a6a808bb3cc7f6002b87789912afd98bce26ad8b3",
         Msg => "0c294a318b7c1e884649fe54e4a87285e42f868e3d0a8519414e05f9c78b236089a11052cbd4cd593e22327b23d33569b35369f9bf3dc5d694b8a7762106184d5c5a5241e1ea805ddc46c4c92ae87efabb0ccc263bc24dfbf1412b90e77e589c4bfd17e615e7bffcea5ebb28400dd6a0c403b6fdf8c1a5ee2191982e601a69b3",
         Mac => "28f1b663213043c4d4fb312bd36d85fbe62c8008ce82aabc");
      Test_HMAC_SHA256
        (Key => "2a0466dd515d2f48fec5e78e22bb22c606b09e8184691c5177a46e8c70fed24dab147ebc41e97c8f",
         Msg => "d60812433098c44623159153de7cd2721b349f685c43388a74c2a3d04a8e972ada4199177c61657369d78f907ba26a8934cc29d3029d4415c1101e3a8283e4c48bb2b8639fe60fc67f6a57b1b03fde507f10efcb43683e1ae223851b962370e1f144b74f1f9189e66cb831dc05bbf46e03e93877a50dec40dde5239a0fd5022a",
         Mac => "7c2e5f1fdbda3c153536ec7136091eba0ba525b950bfc84f");
      Test_HMAC_SHA256
        (Key => "3a4182af8c3914d1df57b6321fa5dec68748ad746e0369bb64fc2d9b7dc3dfb3ed9063a7d5cc0ec4",
         Msg => "3db052695a599813309fae5cf5b19690d3e1e63b3caac1487ef10766978bc9b04a00008c728e7ed397712433bf6256d2865eac3471a8ea5f8011333d02777941ad8c384deed864d47e02a03c364bb086245b3130de40875a16b418296f9eb8698fdc63767640325c0ed8883d03738cf3d460ddf72b7981816a611ef186096c6e",
         Mac => "dd3334fabe8d0d51084c1e99a2a7fa8548c4cbbeec854fb4");
      Test_HMAC_SHA256
        (Key => "56e8ada1ebc8706b94f99bf2290365222f6619a7fc3161151cd0c566f4266faaa5dc31fa34f8c9ae",
         Msg => "9ae4b799989bc132e5a50c4fce6d6e44e2940c6ba7dbb8248b447d191d7477c77d5ce83a111889177a171ee0c77d4d74e8c5b0d565ab292e504976157880050ddf99094f6e2ccdcae84148681db6f39360e1d7f83a75ea8a60aa9bcae398ac46a7e44060169f3551156bb36e37e005a9312ea85a8f03a240a5af15c2c786147b",
         Mac => "bddd77019ee3e2a16e65713089b23f0ef13e5f3ae6da5052");
      Test_HMAC_SHA256
        (Key => "1e6d00b386bbbfb7f44001c5915448a516954d7a2ae8f4e9eaba807dc98c034a9aae19d1eb4ad624",
         Msg => "009f5e399430038250721be1796535ff21a609fdf9f0f61266e3af75d704317d5506f8065c487218e99eb4c3d4546c4d607016901138739dbdf437a5e6f5021a47d69211ad0237eb08768734c2c952cb4f69d94306273a8a2ff62fc85deff88afe99962030683a43d683fdfcebcad1c11718b8e080c53421e370fea6e3fbfa17",
         Mac => "7794f8fe7ace77512eb98a5459aaebe28ae1e8c62832b5d2");
      Test_HMAC_SHA256
        (Key => "e2127a48f615eeafb927ee53222f5004d11dd2d3a22e5377826b43f08174586a297b82630e932210",
         Msg => "1dd28756d292e5a4f3537e88777933335a64f79a4d50257aac791799b083f450e61ac946dfd6dc7e29613d947fdb9d433d7d632b177dfdd1093274e8917944cf1d576a5abfe0bed528578346d4963df382b0c224e7d6942aa3776ea074ab1df1aad2911bdb7834b2d77d7b27de72ba4a11453c0e2721938c61902d4bc0e328bf",
         Mac => "d0119cf3ad1dd9e917ab325c0b85927819ed606084542944");
      Test_HMAC_SHA256
        (Key => "ee0a81a8bd52c9b1422083522d37f8071896ba625ffa22ad32a4fdd1e85c837796b6896ce194f74a",
         Msg => "0c245de3b250c33282ea1a02d007f03b34ed427631283eb614db4d521f555136e7e42b4cfbee8134c63dbe3bb79b5a8b9f9f5b9f5ac61cfab1c54d197f1e3ba613f251eed616df952d691b88a16466343ef2d0f63882ddd2d55b8a6786308b2257f5d7b38af166bd7f1339d2d8899c9eda8fa86215850ba547450c267eb3c914",
         Mac => "335ee9a4c96bfcfc38c76f7ace6c84adfd0a57a94efc23b2");
      Test_HMAC_SHA256
        (Key => "d4254694ca38676404cc2cd6a444f61e230c188a9f92d4ad769287bc1397203808bfd6cd5dbe1b7b",
         Msg => "d106a9aec442fed61629e77566f789b28c2c2c3ec628878a12f73d37da6ea7ced677d4b12fa9ce51e01c1fa2627b94cc885a4124a8cac55afb2bd0f34642e2faba8c55f319d19d111bfbcfa9102960e5c6002fbdad41c62339a1dd7e88d5205a45ec335ecce1f27e8f71fd72b82a746610c5fff31fb5124e95006fbfe84eec55",
         Mac => "5adf1391c94a60602cefe1bcc610060de90a4b7b8822db1b");
      Test_HMAC_SHA256
        (Key => "61b83d7ff9b82b32a89225eacd7c9c25807c8dbac8cf56610e88c875d2797df99d566bda3718ba73",
         Msg => "96560a07f7e398fc739648ce9a924350fbf9b45239ae7c7f626026867dc41d7862211c71cf12e77bb78839afdd0efd9ea251c0ef1bdf6749672f1d7340e290b9cf485d92c526c881a7b6b13969f0c4043f08ef65b03819fcecbf11ab5f2ac4f786d2b4b102a6a5d5eb2a99b266c0ff4b7a2728fe1f41fa639819e877032422fa",
         Mac => "312cd3f6c27e3ece5ed08f1020c815277f7e98bc3bcd0248");
      Test_HMAC_SHA256
        (Key => "adf13d80eef135f3cbfe63ac19e8679b98c01dfd263d72db335e76d47551b31ddd94bec6c95a0b3f",
         Msg => "81b8de7e17cc5ffdce4f2213b561d67d244ea591aab5c37f47e946d7db97384bdfa9eab7536b8c5ef7ecfb76bea8dae88063e451ef58804ccc9396f35b9ca2a3145507009b25a539f256ad8eeebcb40fe79807a6b4bb3f57d6ef15c7f49277fb8884db63d744d3172655e1602be78d7ac2b3b698e1272629cec3695a8fc3dedc",
         Mac => "a80b1a06ed13f5579a785f7965ab180908a07f152ea81e2e");
      Test_HMAC_SHA256
        (Key => "f870e26dd47b20d386f63d12458c46d795fe0790bdc81d2e7c025329f8842bc5f74dba955126b93d",
         Msg => "f4d6aedd9a34e0a1822362714d4e81794b53b266417678c16a97887bbb612cc96bc5e532b3a654e5d3d65a5155427ff09569906381138cc49e3fc2384c5d33c34abd3d617c487b52ec6ee7b5105f41584b7eb5cfb512b8c31f3f338d5236e30398a8ff927e801c8ed7d14fc5040d915a737967d166ddc266f68023a357530431",
         Mac => "68934f2d0de64c4e4eede0b1d867630da790c111371458d5");
      Test_HMAC_SHA256
        (Key => "cd4f85a044eaf7c5a9850d0d708f0905049dc27718679a8f3713af3ca3b756d95c19c50d7fb90ff0",
         Msg => "bbf96d794a6a062fed76429a8b395e5664c6b1b0a26bdf083137507ad1bae0bd6a0cd84a9f111ec1a5faa889560f36b781ac4132858a2e141e40c8537e0aeda0a0c8878fd94abff9b0ca6d9fefbad20ffac189cc6000bba9b09993768e72f1de053663901f9d519db3ee77217fc29826760a71c55b53ed8e8f49972b287a543f",
         Mac => "de9a7e21d30725d253fc4d09a3fd21530d788795d672c057");
      Test_HMAC_SHA256
        (Key => "e6e97a286f575855cec8a0f4d06327929d41f81d3fdaf9f65ebdcc474d85f4974b08399c02d14d50",
         Msg => "99140d978b2e37f32684f3bf075c4678fe4b3a95fc93df7532af9096772b7707eab95420d9827970e2ba19f75877c395e9c32ac37def2781602b018fa454ebe0c10dce4c7f11498516c8f74c9318f0e57d7d92c8b95c8199ab94ec5a9e5712e0663805834384ae1a09d612277ee6d34e04a2fa0c7880f3a55912d95e2ddbf5ed",
         Mac => "61a0693f740c3b121238cc904e98c671563d506780960a00");
      Test_HMAC_SHA256
        (Key => "d763c6360763561ed2bf47749080549b6e2db87514e1ee1c85a0bbd346eb6e3cc29267cbedcad67a",
         Msg => "41677677d9b19e249d4488c3eb18153d5b705002ea6aae4258d59560ce421aa4c45e0f30227f3d35a57cee6685c2afad55a4531d2af33b29ffcfd51358bc63a726f9fe28eb0dda8b1ea2cbe3d196081d915030ed8e508a08fc0a9194b8f5b0dc2fdf4a497c83fd8ed05d282217bdaaf3d81bed595daa2448152fd0cb361489ad",
         Mac => "014d599f9490a22b69824f8cce92f30c0542cea92b621a10");
      Test_HMAC_SHA256
        (Key => "a4b540971d9bdb20b47e8282cac841a86fd94fff27b4eecfeef893cb7b1347e7c2b24d69bc7b0543",
         Msg => "50ee2389b8b70182548ccd7e82de8496c6b3602bc99efc7ca2efba77552762d099af0b51dfc93f718fc65a27957a33001cedfe70995371650c3e26228313414bdfba523cda9a7d9f49c5d83e9f6f1415b3a560acc33c8aa4b807678fab4d7605a979c0f4b314023709f10e6aa9a76ffd12444c884d408f5e2eb04565d8bc4825",
         Mac => "431d287099550ba9e523dd1308b0514cdc5faddb04ebc4c1");
      Test_HMAC_SHA256
        (Key => "9779d9120642797f1747025d5b22b7ac607cab08e1758f2f3a46c8be1e25c53b8c6a8f58ffefa176",
         Msg => "b1689c2591eaf3c9e66070f8a77954ffb81749f1b00346f9dfe0b2ee905dcc288baf4a92de3f4001dd9f44c468c3d07d6c6ee82faceafc97c2fc0fc0601719d2dcd0aa2aec92d1b0ae933c65eb06a03c9c935c2bad0459810241347ab87e9f11adb30415424c6c7f5f22a003b8ab8de54f6ded0e3ab9245fa79568451dfa258e",
         Mac => "769f00d3e6a6cc1fb426a14a4f76c6462e6149726e0dee0ec0cf97a16605ac8b");
      Test_HMAC_SHA256
        (Key => "09675f2dcc4783b599f18fb765583668a0fd8ae4096f6fcdc60d4f35b4130fbefcd542ffe7459d2a",
         Msg => "0cf2198c31376f5c8915660137725f2bbc180a986e5a7bda27fa81593a4a339bab92cbc39fb2b8581108ee48c794812d845a72ce8008c9e915d9e330bbb90e9136aa53ba0e6693dd4046d6b03362dfb9edfa04c887153cc5de677aab8c7839d517035879679c29727e96c5426324a2575fbe678d6cc7fef5eb6cebd595cfddef",
         Mac => "6b142d4dfe217f1881aa0e6483b271dd5d43f70b85605953a0fef272ddde46ca");
      Test_HMAC_SHA256
        (Key => "cfd4a44910c9e567507abb6cede4fe601a7a2765c9755aa2cf6ba4814223811a26a8a1ef499cebd9",
         Msg => "3fb301cb4092f9623aa5ffd690d22d65d56e5a1c330b9c4a0d910c34e391c90a76d5401a2d3caa44b8c5d5aef3e928b90d2ee233e9f9a2cec4a32cd019d06a0dc1fcb1125f5746a4fbd32169ed7bf0e4fd065fa7c8ac97c366380484495f5c5b6850dd1c9d8cd6694cf8686e46308ed0ed1f5bdf98cd831339771db63de5a7de",
         Mac => "20153bf8ea2953c48251ebcc4161f8b6e28499e5c76c24014cff4a9e2f62d25c");
      Test_HMAC_SHA256
        (Key => "5448998f9d8f98534addf0c8ba631c496bf8a8006cbb46ad15fa1fa2f55367120c19348c3afa90c3",
         Msg => "1c4396f7b7f9228e832a13692002ba2aff439dcb7fddbfd456c022d133ee8903a2d482562fdaa493ce3916d77a0c51441dab26f6b0340238a36a71f87fc3e179cabca9482b704971ce69f3f20ab64b70413d6c2908532b2a888a9fc224cae1365da410b6f2e298904b63b4a41726321835a4774dd063c211cfc8b5166c2d11a2",
         Mac => "7e8cba9dd9f06ebdd7f92e0f1a67c7f4df52693c212bdd84f67370b351533c6c");
      Test_HMAC_SHA256
        (Key => "9da0c114682f82c1d1e9b54430580b9c569489ca16b92ee10498d55d7cad5db5e652063439311e04",
         Msg => "4953408be3ddde42521eb625a37af0d2cf9ed184f5b627e5e7e0e824e8e11648b418e5c4c1b0204bc519c9e578b800439bdd254f39f641082d03a28de44ac677644c7b6c8df743f29f1dfd80fd25c2db31010ea02f60201cde24a364d4168da261d848aed01c10dee9149c1ebb29004398f0d29c605a8bca032b31d241ad3371",
         Mac => "cdeacfcebf46cc9d7e4d4175e5d8d267c23a64cde83e867e5001ecf26fbd30d2");
      Test_HMAC_SHA256
        (Key => "aaafd08fd89bebe239ab65bb190b86d49c5d39faa50b1109f7dc8b179bc693f0810449c36a68041a",
         Msg => "44131187c07a8e3979254b0c1d1cfa8081f0beb8890633744932af3f6987c7eace6e153876f639dba46b1e9f3e2a7fe673b3a954a00082cb7516ca9a54d9a1f1f924499960192ee1e3b623dca4a9efc92a6608d34f769efb5912db5267f06a6b0f5d3610458c74347e2ee32916425213ef2f649d5c1090ea3d4f6bcf6b752a3f",
         Mac => "0c19ab5d4ee7b64396eff7b2ca9efa5ca7369c1a1ed14952445d2fb5ece9473a");
      Test_HMAC_SHA256
        (Key => "b06f7ca7a5dd8baf2ca940811edad87a33da666dc427bcf4d54a8e03520dd5c399e9729d39be1494",
         Msg => "32b45fbcbaf262bbe347360bd6076c43dc26ba9573fcabaea14595de886ccc793b09157dd0a85d74b6ccab9c49335446a45c6e7cb64786e6997c96ef1e4e3123ad6101db4c6a731dfd36b1be4deed1c92a994b25f5e2b171d81b9a335a83e03230c40b2056c00c7c5f8d2fb70abe4b9615e53bd756569217072d8bf362923f6e",
         Mac => "a9c9d3993fe7ec4c2033ccf3b73b3407cd999d67455b43a75d6ba97efda3be63");
      Test_HMAC_SHA256
        (Key => "2dff35c2fe5039123d4c5d9feb7d5167e3e959b31841abec1e5b18b0ece2ef25e04d1f8d030d9b1b",
         Msg => "14890f3b2ee63746c8249909013571a403eb54273760090db5959b06ff59acfaee6d0c4aece58b5964d10b4b771dd90cf1b63d947bee4f6a12220d67b79aabbd68b02a3850352cc33b10072d4c28182df2855aa418b236239c659dad036155be6b9c908bc09dc38c3329b538e81ed710ef9fd3de7671673f3da5745f4a785204",
         Mac => "468d8498d46afe74a0ffb541b847bac724faeabd48c41322bf534b284c4e9fe0");
      Test_HMAC_SHA256
        (Key => "9794cf76aeef22963fa40a09a86bf0e2ba9f54f30f43bff09d44f9d28cfd7b7a45002797cc1437c9",
         Msg => "3e8a9030eae1bb6084cffdb577623c4cf94b7aee3d3ca994ea94c12acd3e1194cad6d2ef190e0219af517073f9a613e5d0d69f23aad15a2f0d4e2c204ab2f621673325bc5d3d875984145d014bbcb1682c16ea2bdf4b9d56ce6da629ca5c781cfce7b1201e34f228eb62ede8d36cbfdcf451818d46721910153b56cfb5053d8c",
         Mac => "29973999c4ec891154b83ebe5b0201cf29205d68e7be2c1d59bbc81658d6668e");
      Test_HMAC_SHA256
        (Key => "c1d60814376aae39c4111246353485958f95558fa38ffc14e4a0981d76249b9f8763c4b3e2ce4ef5",
         Msg => "97d29ac5ede94c0a5071e0095e6102123d1726132f9dc102672ab87b1cec18abdb04096c21d3fdb129742d250389460fe63b5f79c77c2f912a8f7d4f39cbd758139c872366cac35a40fe248322825adf57481d92832e66057f80e08964be993de6a0fe31e45806cb3c17ad6ae4d2a44a374647a88c3acf260d04c970c74ec720",
         Mac => "50db0ecb5b31524a6914264930abccae0da07f01a2bbb9408207156f8e8a340c");
      Test_HMAC_SHA256
        (Key => "ca5f3eb9308604f9fcc2af1c6a3175cd8a75045593b473bd7ae37933c345ddb0982e2dd7180db31f",
         Msg => "8734e49e3e629deb352c77f58ff4dcce2af3b1182e7d896ae68619f6cf66ed69efd95913684ab1484d51bc06b47a67d70d48b7f9b27901bdbf8c5d2d238158f1f7e0e9740ffca742cf7938b5400c0dd063824c6bc6040e905499cb2671ec12cc47507e085a01e5a163acd2495b32367fd6aa5ab492a518ad50b54b28e23084c2",
         Mac => "a5772a3da86365b46638f1e97037fc0d8351d2e19ed929f85448ebf4e8379a8e");
      Test_HMAC_SHA256
        (Key => "808d7aa9aba6a40d1bc43e9b932ec8e9273b892ffc0a769e4f7255f3b83c224bb090b23952ae9616",
         Msg => "61c5be972faa61f67bcb332542c0b8a7c74ef67cdb95d6f65c8acec8fca8bd6043e31677d8de41e6fc5d3ebb57fd8c8cf723490b96329adb1b014da2648cbd6043e9f6ffc67e1a2bbc72046374612a50c854c8565af03b6a1eedaa2319caec1368bfa65783f4b46dc3f0cb4622545c9c43c9bb86b237804a6c382e72a2cc1222",
         Mac => "5f1b8de0e3b07da6f9ce1a494be5712e54ac16080bb4f6d5373620d86d5ea5c7");
      Test_HMAC_SHA256
        (Key => "d8b994bb8df02d7803ca2e09d601b918d6b5bde90b611bebf70e078d1ac7b152bc4c2528e60b70f6",
         Msg => "b31d11cb4f5c572ccf3405c65cbd218ee8abdc08b6c82e5d1da2baaf8980f7a9c29b915a718b0d43e000adae01b29342b29b28d53f63bf81281c76fa252f5d1e6896dbce224c4dfd4802ef0697140043d6bb21db5b84ffdbd001318937be64f52c76b5d06a875e8191a4957627cab1b8dc758fc3121334949cb9b303c6155153",
         Mac => "8e44d685fa79395b4761cab89688e37509e69ad007a2794c8c0b4152b67036ea");
      Test_HMAC_SHA256
        (Key => "a89bbaa86a339951ddcd37799e21b5d1688e4abedbc72daf7cc9b5adfe10be34c00a504196cc7bac",
         Msg => "3ad17308cd259688d5b52c32d01a3b868bfaa4758bdaa5ceac34a1f908ca24e71a39224924d17f00cda4d4d50fdd716b50549e71cf5f271c42ea17d5becac32fd64e0a1b0717dc5f542af9442d44fb8f956e97b384d020458aca4cb0b6413b2ab637b5e73f9fb48cb06f22e6f2f6e3dca27016a272d89830ccfdcaf3b9d895c2",
         Mac => "905d55da5d290d023f6940fcb904c50e70181c95000eb1e6a33aa01077692736");
      Test_HMAC_SHA256
        (Key => "a9560fd61746d7f986b691f070c920256a535c21a64ab5a2bd771aeeab7119681bcc4761e68ee230",
         Msg => "46eb5059055d3345c1ea84a4ebd2d7cc53361707eccd70e7cfd86bda83585bfe7c7ef937e1634b7e93f9ca7c6a42c357c2bffecc362c9e7eab6a488d91bd876b65376feb7a74819bfa88cf542736610fe763d6fa80c94ecca0f08855a05a485909fefc9e58f99e44fe7fdc55ab17779dcc08e9bc530e4a79b65274593a996671",
         Mac => "9045dd3fa6e8f2ef7c57b03932d244186caa1bc1d4b694c47e1f2901d9eba193");
      Test_HMAC_SHA256
        (Key => "f987eb83a3fd6d94ebf3626b7d34fec23ee06c63dfb4078cb38bcc97bd250fda0e286ecd4e64046a985bdfda8b",
         Msg => "390a9dc2ea20221c5993c581892eb4b04364294fad919c451e83376531398a4c18ea808c334a910ae1083aa4979baa172f3ebf20823930e238630c88dfe5632b3b4042f6dd92e588f71529996fe840e13212a835cbc45ef434de4fa1ecb50fd14913cd481080875f43c07aa93a9dddd5f5e7ced6b1b88d42b9fce8f87f31f606",
         Mac => "0b3b220ee7a4fdcb0d17a5c8b595b981");
      Test_HMAC_SHA256
        (Key => "ef257132b7be124ea0886d587765e8e70357959cf39ebf621420c3f3c70e219fb3c5d349b7f2deb222fa26fa27",
         Msg => "f90768954cdcbd5705f9d318fca6591787af840a921fbd06f24b979ef612034f3f64c71cd2012c756c83f75d169f9bccf8a8ad52725498fe69c3927edfbdcf87c73cf478172ace3a1e6b446a181e8aba00209894a5d2db01001d2acac5b3fbdd3897d7f142df0b6dc4b9a1862bac8ea845202d185321ecd75f6046c9cf7af116",
         Mac => "a17d0e0f021184a3937222de81be627c");
      Test_HMAC_SHA256
        (Key => "2cb8e269726b75e3a6258541251f6e3c5184c5e6878decea51eae315dc656115acc224818ee9851ace474f51ab",
         Msg => "c1d80128fa208ba18bbb13424012ea651ee75e73f796e94c3b9aa9e911521040a605dd67c5254bfda9d088c60f9c68958f945b6f2b7e9ded2960ace21e42ff3e4c34f5322d930c955089538764d3225493c7089b119505aff4cdf93d46215d2f586d31d15af4353229ec5cce683e7e69d2874d3ece628a5944e97942b07992db",
         Mac => "da4571749322008e73dd436a13c5f11d");
      Test_HMAC_SHA256
        (Key => "1eea906ca11432655750a4e1af21eb1e03465c6d6f3b0fd8e20391077525d965fcf57d7edb1426ab1c3a42f2be",
         Msg => "f57ea84caaa2af18dd7efdca356b9625f9e70d3a803a9d31e95976460c0a5512af49570cfeea0f4f3581d69ea07f62a5c59d9b81e07ea9838f8f5231cf33838e271d2c9c23fc511e045e5fa2b6cebcbf0240a19c05b02cb1e105b1d2b23b5269c4c1cf0303209f0eb2de3fe060a2cafc1898ca91d9174d4445823c2f9d6ce92a",
         Mac => "20cccc1ea0a8a89b3bc5fe3d5a9c2b24");
      Test_HMAC_SHA256
        (Key => "b2f1adfbbde4dd9a9674166ee08c2f4341072475b9b80b1032ad4a3658b408c1aa1fe12ad1c5deaa3149a49ebf",
         Msg => "33ca6eb7ec1091b406cf64495ccfa2169f47b3b590477d4073537c14c05015d51ba527b3869ae4ebd603df906323658b04cb11e13bc29b34ac69f18dd49f8958f7e3f5b05ab8b8ddb34e581bde5eb49dd15698d2d2b68fe7e8baf88d8f395cfcafcdff38cf34b59386f6f77333483655ee316f12bfeb00610d8cba9e59e637ca",
         Mac => "5eeec5bd9583ce715d613d4c04a702f9");
      Test_HMAC_SHA256
        (Key => "a2617206e2b382078fddb0af3743a69a5a7484eecfff6cd96288443bc21ab79f9bbf7d70ff4edd6a0a85704ec6",
         Msg => "74c4ca4db1aa812b4d75852c6717146351e83299448ff84d52262ff99d991d97c74f9f64a90d78e44817e926049882491343373f2e3bb6d18a30f8e30acb16fab34d5ffb6073a736b79ce1a25b2df16a6335bba90c4d8072aac36a14e5f7659c2104319b3ea3b529824d9729d3a009cf2a04e660448efd399b25ad1394e3b285",
         Mac => "64d5ad7697a29529ca3ca4ff65e7d735");
      Test_HMAC_SHA256
        (Key => "7af197b78a27038b0cec128001ce6bb7dc02c0258956f62ead678676301423f4f9329d48f881054e6adf12f358",
         Msg => "68bb5b6289907589f8d91e46d44417ea80bf6be10245f52ba9f82211f371f810ad54571a5c277ffedc64d32447ccdd7d19ff91ba914ad6bc5ac0424c6a8c250d2b85caaed803f9642af1c098352474dd8cebf224ace82a33981edf53c04aa84927773b88c5cdeaa52baa6e0b65f4e4f024ad15881dc7fa78ac3a808dbd5588ae",
         Mac => "c4fdcba979357f639cc6d89e7970943a");
      Test_HMAC_SHA256
        (Key => "96ab1d64acad8cf69651c13e4eb42d7382e38019f3a927771ba6134c12a1bdbeb2206793fa35a4a3b09a1a8d4a",
         Msg => "900e4152131d8c4dcc38a9e8647234dffc7ce88ecbbb65a8089d302c0a2efc95aee62852f9c58875fea368af02c1ce7cdfa3009ba62246c188bdf18ef7309cc00848b2a71cf531d9bfa1ad26d0c097cee3a8bff2e3a31849fc43bb14b7f62f5467dae83ac5d30ddfd7da7f351698163ecf332e7bca6862a82ada97a694a93db9",
         Mac => "ea411f749902bb0d2fa36e07e694da8c");
      Test_HMAC_SHA256
        (Key => "582c13a6c4d497e4edf69bde35beaababa1b068ed168af20b04cc2f06adf0478210ebfb27640cddb453af27790",
         Msg => "7159ecc145a3f919044c851a4eca428279626e68cd8fa4c5f4a7f932acbc44f3bfc0bd3535edca94c86415e09815e22120dea0d869f7bd887d8dbf751fad91acb9641a43962514e2516a1c838e9e0575e73b72a72a30a423c18590d97141359e488c2c74d011810c89a6c189962f5487b7bf0d5c7701009da7d794e50a40d9d1",
         Mac => "7a699c1ce4e323fe1b9ff6dea2038aa8");
      Test_HMAC_SHA256
        (Key => "baf1d8aa12f5ea6264d122938593a8d677c82a37ebed7b43042680625e334c674f9f8a666c3a1bc54fca019698",
         Msg => "939bfaab9f60369542928b1490894259c22706747f0c48215b08e1e59ed6f95a460728c74f3cdcf43198fb3dab75c9e4bf560bacfe1d6da3057f213f48b4c9ac0e739765bd1db2025839dc50462053a755f9f478fee8a626eb83f617b686ff0af4c78dab726c8264be5b7877e9f2a74a8cf9090109d4bd5213fdaa9571b2641b",
         Mac => "e2a380effe8de7d29948c5d9d7bb39a9");
      Test_HMAC_SHA256
        (Key => "735d943cc93f783050c7ccb09acc5a6f60af4efbc8919793e7c39038857ee00621d59fc535e7babcbc5998c5f0",
         Msg => "29ba205089b12e8be5b422faf99c3d69aaca324eeb732db8e13c148245070dcc0b0c40ab412bde2039806247ea3917d194a4dab4a38c2121d6c63cb7a007dbf6cff9d1f66b8d1759e192147e60871bf784ad363e326122a3c3a99a89640dd9d2bca85a98d07ee21e2410c006232e53c4c10dce525f993825ef0cb76158c00d49",
         Mac => "54e871ae687626fee5669ce20cc48041");
      Test_HMAC_SHA256
        (Key => "c782597141b52135e34d240df67b9bdc274f2d41e6866e0f0da3a6fec241d3a09ea7f1960f9d7803fa7e2741a5",
         Msg => "f7321718bbd3b401fb5d72f2e8931a5ebb18d2a1ecd4f189a59912157607687c4aad51719a702da6e031708f4faaf668c1999779f121fc99ea6db0f1bf967a027dc7ebea5e9f33e23fd6390c5424ea6c1b5ed0338ee3e7449d36adf1dbec790578c90d086f266ebe0095f4f161c89d70b1afa6582de15d92a63d319d33d10b8e",
         Mac => "eb5b96d2f51d56464b95da4927ec5a64");
      Test_HMAC_SHA256
        (Key => "498584e364f632184bf26a253d0e81e146730963b785eac1d5c2b51dceec34e3f16a464c1dece9277a4e99d868",
         Msg => "cf25d619fb46bfbc39557914dda02d767ac511120d173b787743b35b3134cb943b33b36955534810720c2d6f6a261d26efd87fcfc2323b8426b8cda2965098cdb35e7c35802daa17d191b78601caf06be4aceecbfcfd6a48f01f52eb39ee1b201fec5a02e49c8ed93f2b40e10c554f4e4187858c24416dcbbbbf69bb84d8ff94",
         Mac => "020d5aca34d8c7066ef5d8c9b3429669");
      Test_HMAC_SHA256
        (Key => "e4298464a0457dcf98ef09cc00d92238d06d9a7574b46769c5773ec939a4639756f2bfe96dc833ed845c2c2a94",
         Msg => "e2a26ca137027066af856453d2a4adc4d5d0c9d5bf068f8acaa4b74d0c7b9c9e562541065d98924c17fcedec68bae1c5fed636127a7e2d9bd0e3082df047cd47a6574816bebc4fa36ded4a4cec47f271665f586f149729d2a7ef31c6e61e1fcf98e288baa4942ed477ff8159a672662fd41438d4d7780c9616713a023528199e",
         Mac => "0d700ca9ffc418b29fc8e316acbc1abb");
      Test_HMAC_SHA256
        (Key => "28ae9e327911b76898af1fa0de56069e0d8b67bd2813828f87b88dc42a49a74d4ee30dc13e6f90ff6c6c4715c0",
         Msg => "3b9a4948d67dc894d70c9ec37104a7147e22bcccb98983c22d648b21edcc986a06ec3bb8b263a648cee9bf388e36738f70204d7e6e0347e67865e01921da6ee59926b6cfdba2ba9c27e1d216b392fe0c9ea87b9b25b994ac19a4bbbe9077d8e6dc90e113b902ab97ca3a00e347e2f192f0056daa4574131ef8694597a36b7e73",
         Mac => "6696e3812da4807f05b84a29ad9143ae");
      Test_HMAC_SHA256
        (Key => "9117cf3ce9f5c6e19752bf0b1cf86a78ce3adbba87dae1399a2a937b0b722ba3ff92183871e84e282774e10de4",
         Msg => "935a3c27249dcf92aedac8dc76d22ff7742e5cee57711778c92afdcdf36e26b8448504ee6ee48e9eb25b9e495e9098d494ac4ddc4c541f499cdb652638b611b0353090ac125ff1fef8564a78419c57f038dd65951fe06e8377b986947b407579eec1a60a16f540db0931921027deb472e8296bc2d8fb4e4ddf2c27c0c6f49c3e",
         Mac => "4cd095ce641f217f8b5f355152eed00b1d9fd721a08dc5a0");
      Test_HMAC_SHA256
        (Key => "363b32accfa593e454cc3ec83b9d775a0dd027b017ca2ff863c1fcb9e6215b5cfb2e8fea10eba2179f3bf88061",
         Msg => "548564e5b7370426d575bbe8175b48c244dedcef3daf7252ec625fb777d02a5cb9ba9db0f2af1c5abd2f367d43107a3aaf218c77e20e78df6783452aa994ce9f635dcdd759e539c34649d2f11516fa0a53f6c6a0e58f5526f6a86040348d133e3cb51be252a3016a560ab6caf3346f3a1aa4b2f0affbb12f8218d8808083a240",
         Mac => "646abbd426255d2e369b7ac9eb3c3af19c7185ecd28bd82c");
      Test_HMAC_SHA256
        (Key => "134a50abffc94d8540d7ec939b7a28b10916e505ad90843d08b4b51770d48c27beb2d8d548a1b0a50fe64ebb39",
         Msg => "dd802635f714060381d2ee1dfb50f2daacc637598965fa7158ead3eb15723bef95904dbd699dc99e054f5e19228d29696082792f30f1d565f1c8409359f7bb4517820cbcb6d5bee4c5596986354433bf02b597b1160065786a460a5f6e4a1254ab7feb9aa666ecbe081695ccfd1c19c2da861945023bb3930a8ebbb91b124806",
         Mac => "3d731839c004ecef8ab60fafd811d0bbe6e306f7cc802bdd");
      Test_HMAC_SHA256
        (Key => "c83ead9a131a1d7d126b88642221ece7d3a6ddd6016ecc6f40d089d47e1407bce3cd6068fc6918d91906a640f3",
         Msg => "e80a112713b2e0aafddfdb71c091141719e1501c1ce55ee526d4a804146a08bab28eddba76335d306f7c2d0278232f56b11b9b543074512df3806d5c19341c2c52d0af7a95c3eebc11c8af426556a7bc13377ffd32762afe647f77260882e2c8b118b0eed6293b55cb0d8ab8eff12451287d269e8cb49461611bedea481d0298",
         Mac => "0a4f17a280f9017f1435cb8a11738fda4f14e3f222f06b86");
      Test_HMAC_SHA256
        (Key => "430a7dbd62b3b3cb6a4b2024bd796048ea60990d8222f94228a26093e88f59acca9e4fa2a616fe8e3992277b79",
         Msg => "7e5d6e5e9491a965968a08adcbfbbdb19949f00903f7618270624e74aeae975036002079b2ed7755bc33b7a3e9a7ac0f066f3703a171f4c1cc0b1baf1d05a4f1f9c4af3d12c022eb2f38944c2c246a3d416b3ffc87568a3ab7447a7135a025774e11e254bef0f35176ff68519c583f64d2a3d09abb8c6915bb753562ff67620a",
         Mac => "5007afb09312d144091f2b35618c26714bab8784d8be35b8");
      Test_HMAC_SHA256
        (Key => "4953408be3ddde42521eb625a37af0d2cf9ed184f5b627e5e7e0e824e8e11648b418e5c4c1b0204bc519c9e578",
         Msg => "fc0624c9d2fb237707df2c7bd9090b031329835432d99304c575f8691a2df35116584cf3650b9726d4ebb6d1fa3f9fa31e4a600455d7604beb15e73104a5e08583f2de222bc15e1f04094c450104c8c6df86292b508e428f591ae50bf940a6710b7be13d6d43ffc862e0f4bf357f0cd42086e8b36b25c338d82dfbdf3f26cc7c",
         Mac => "08c4699d15dcaef9e99556ece73793e006c86d25c8be3fc7");
      Test_HMAC_SHA256
        (Key => "da6d09682610d23a666ab7f63147a1f05db8b3cfc2c12de3415290b9067803ec09d5f53ddb4e04e69f031d2c56",
         Msg => "e35dc1d0e414ae0e586ebec9a44c1918d795db378a89177d0b521c8ebadcf6d2b2e73826ac5bf9d121db1db9af9cd6d7be7869e8633e3665854df3b63e6138a383ac400b0829eed85e2d0e325e3fdef3cb29cc5b334f82061640201a4b8bc8c59ed460e7be26930b578b199c7bda395646d18cfac263034608532b24a802b022",
         Mac => "66a57a169d8d0ba263dd954b342919f4622592eed20c1981");
      Test_HMAC_SHA256
        (Key => "22f6c7ddb0e46ecf627aebd9ffad6f36682ef5c98791d25e82af8d333449f0b7ddee5f91181e69e40eaf9dd1ea",
         Msg => "dc4354ff557dfa58b17a0e38f63a61c20e0fd1eb6cac102cf37fa77913413a7735cb0dea592bc76cfdf7766541e1d4374a8cc9b9e49e30e76b17ded8ebe1e0f086a7055616eb9da814537feeb94451cd62b203fe39379dfe12623b069351553d9882442dd5e60273be3732bba38c60ec202b89a0b49eded7b009c5ec53ba21c8",
         Mac => "7959e5367720f3af55ae91843397134032ee73de6a8db8ac");
      Test_HMAC_SHA256
        (Key => "2e2b999290c9b4a3760c4bf767ae44b28a8d12461552cd39095088291dafdf0df7c9cfbda2d4cbb53dc20b15f0",
         Msg => "36581b498cc8b9ea79de28ca91a9cd0a87e30bcefe73b9e59c37d3a860016f2436dff37bc9a086879993c4c14d92b6614a3f01c7848e5d1a9484492f0c3efeac0734a16d04bfbc26f4d9ef4a9124e32cf22f80655cf460755ca583ad12a8444cd0e08be8e42e450fb137112f05683cb3a638f06f2eada83e1922e7e91d472a4b",
         Mac => "d39eefe024ce0b545d77ce327f0731c5581095ca734c21fb");
      Test_HMAC_SHA256
        (Key => "089aa37f72b2962c18fa4e9858ebac2fc1655ff41ba30715a76d9ac3a88f0740218b1a3ae18ba057bd99cb111d",
         Msg => "45ae84fe11078713bc87c465e8d88f0b23e2804a6a3e19afebeeaa5a0f4c729db84107c6c8b7f838e251b0c174599d27f5fa92046baf6ad431fbef4df75bfaef0a79dbdbd6a2fae8a97abff4b9eeb078696bd95fc84d71195a9bbaeb1cf12989c2bdc7e643aed74b976ab9a7bf800e26079d1d04880276a4f035d4dc86f74893",
         Mac => "3accf0eec5b26ea6c936323b42636e5899f4bfe7e7cbdf3a");
      Test_HMAC_SHA256
        (Key => "4e1ad1054c00b6cdd0267739c8c92994a4af4bf373ba066c48bcb483e38da0e58d5b0c59444279f3181c228ad5",
         Msg => "f6f83ff6ddf386bdf3af9409ef5cef16acb376182322f57b9729f76f0f04dba4098a2a526d55287dc023a9779a7c26a65a951087187564f3db5680a20c4e35ed2b2e1dd8c1ab2f4f96bb90b02342ac8a4aee86a5455f4c42dd8c2fa3dc6272cec4aec08fc13cc2bcdd40f1bc73f6a94ae6867f77922ad5ee0392ac7c6588b9d0",
         Mac => "55adbc7d757e6904448ebdbae5a8773a1781f952f5bdeec0");
      Test_HMAC_SHA256
        (Key => "36e8128355a3dc7ab3fcb28fe93c8e695066334f6610b398737233626cbdf28717ae88cd70626c5d4c6cb9773c",
         Msg => "25c04b857a224389e8a2a304e1bb8ee1b352e4cf5c3cb6e99f01fd9557df8bac0c1241dcc453834b1b9fe97d9639377835f2902647a8e6fa820db5d653a9f12d73233d65bbbc5d7f391ceef9835154f34b15f592344fa5a2e4dd607f5b913f358379a5e60864b96c69a11a40500ace9a1f427bdacb3ad927edfa6756169e5d0d",
         Mac => "22950977bf0f3fb8f4fc53ad2ea2c91d936aa98d06ce067e");
      Test_HMAC_SHA256
        (Key => "ff469d80d2dbef999d7d4815d123cf50ee9c2c23fa2e9aab2c7e3d4ce8afb7f5f0cef6a5d86e4f2eba8fd1392c",
         Msg => "6c15d1686e680c5aee2941900dc9af9d2503b3b6a5623f5c1c04873c939dfd5320be8055b858d050457c468cf864c2b7e1b7e43ebd097ffe0fa14a1c7280d9312d9fccab087747705ec6a2c47491616c096566132ee365ee587c999cb478b550ba3d1e3105ce57016292bcfd27577405c696a1fda1f8d973201ada82018d79f6",
         Mac => "646031963fc8bf827a30924763dca11b589358e7029daf1b");
      Test_HMAC_SHA256
        (Key => "93fd8e208a1d6052388611beb9f047fe91e33afd4bcd74ae6152d5fe5ce3d9073c921e861a24208f0c68477f49",
         Msg => "b99a110bee03f440f15145e28d32c340297fb810efcc36a82e3da171fc9b6d981fa629062eadbd93f35df07614d72d00f205868bd22df9ad3bc6f2b19e8b12473dcf2f7a45109ce33dceaa1ca49d6e78d67ac5f1305b9662740a57f76f32d3e1d9ba2a4e7c531998994d7bbc87af100f9d867e2c527d9531a3aed72bb5b838ce",
         Mac => "00aafb9109999ccf61f6689b7405ad2fa54129c3bc4e67b8");
      Test_HMAC_SHA256
        (Key => "f189baeeec507e945f0c4d628a0d0548eedfd254b11faf25458e29a3456466ed9fe76793f83b8a064c7c534cd5",
         Msg => "c821be1cce09579ea899899d24f8329994c2c839cf0084e27857c688837fb5c4f4f72527eaf7bfcfdda75b37248eb153ba4d31dd418d2fea473643c0c9e1f0ebf591838e349d3ef868f1b67772777a71f8cff5b0654696fe31062ef2628a99095355a0f8b4e41e41d2e162051899d519d6b0dc5c42130047bd2f4dc55761f745",
         Mac => "1c8b29577349cf99f80ca11477f401f61e0b1a4d6974fc61");
      Test_HMAC_SHA256
        (Key => "b763263dc4fc62b227cd3f6b4e9e358c21ca036ce396ab9259c1bedd2f5cd90297dc703c336eca3e358a4d6dc5",
         Msg => "53cb09d0a788e4466d01588df6945d8728d9363f76cd012a10308dad562b6be093364892e8397a8d86f1d81a2096cfc8a1bbb26a1a75525ffebfcf16911dadd09e802aa8686acfd1e4524620254a6bca18dfa56e71417756e5a452fa9ae5aec5dc71591c11630e9defec49a4ecf85a14f60eb854657899972ea5bf6159cb9547",
         Mac => "737301dea93db6bcbadd7bf796693961317ca680b380416f12f466f06526b36b");
      Test_HMAC_SHA256
        (Key => "9fe42dfac92a4a136fa7c9f6e331b5d3a61aa73035b53a8d2517be43721b31b215a96b9bd43798cb5e8febfa97",
         Msg => "f9660fb784c14b5fbec280526a69c2294fba12aea163789bbe9f52a51b5aebb97d964f866c0d5e3be41820924fcf580db0725c7f210823cf7f45a0f964b14e5555070d1c3ddb2c281a80c7fbf72953031a4e771d7e521d578462cafae5a02ac8eb81f082e173ddadc8c41d964bbfda94f5180c8da28a8ebb33be77b0866fa798",
         Mac => "7786c155d10c741b63ec650b7b1aa3bfd71ac71881ad06ae98fb082f17e0caa0");
      Test_HMAC_SHA256
        (Key => "98fff7b5f77326c24471bb9c317490be1febad28e2e825afc41c3b97cc03c963405ce3ec68dcb7b19523b76e62",
         Msg => "64a78a4d6fb8ff3813df8dc022faaf4415e4df2949e16467683c6c47242e5a6b2c02610e5877528d2766b2266ca41000442a956c4b73dd6b10260570c6f506673cc541f50f0f5b021e864a753efab03e2f7c689acfc35f928ecea6c522cbc5687c38518bfa48c19ede887d33ffc23806be21803a3c9793e5ca7c75cfa1783f77",
         Mac => "c02c6022ee0de099e3027850be95a29ce800118ed3a97757dd8ab9e60f69a005");
      Test_HMAC_SHA256
        (Key => "8d649e5ccbb8bb0032cdddbbe44ed0b5bbbde78a30c0f8437bbca985fca5ea08da15c34bea9b5086d2550ae16e",
         Msg => "a7734a0739d51af0ac2c4039dfafa86f36fc06c2355d0f654d4ae938f52fe0a5fd6f5ac71fa80dd2d8396faf76016ee6716a62c1fea640afe23910e684b8a14c47d07b98168915b441cc48668724043074c14275edc239dc09b4d5fa2255652b2c9e94c046019a608ff0b3a83b9ed015e6098d24273864b769c120bbf68f9408",
         Mac => "13e0834e4dd72a2ef7872249bf895da4432329c6e8ade8665d702ba33bb677b0");
      Test_HMAC_SHA256
        (Key => "57958d7e4c73fa606ef405d77ea4977ac96b8813fc1210483a037e7b6c502ceed8f7b22bf6655aa37e38d495c6",
         Msg => "0b9a58cd96351a135c559d17e82ede3434a0caf0befef5dfdf138ec5586793fb2ebe4114b9e2cfbff7a25bef261b253a9136fb7faa72f4cc59e4617f947c01ab308974bdf67ff25ffaf83d9c28fad44520786a94441b96100e42ccb0a8478c43b604d90f7695edb90c602b651753551d886dff77b4804472a835b7a2bc509c8d",
         Mac => "cd251e66c421bad1b37cfebfa3c04ef30b8be4e5526b10fc48fd5bc5d6f04bb4");
      Test_HMAC_SHA256
        (Key => "6d32ba0c063774bf8d0621b208d72095f684faa33ca6f3dc62fbdf95ff0c3733720c6c34d3027b6f2a2bc29cde",
         Msg => "e5804b099ee4b351843adb9c9e3c231773256e6a2070d697a9e29e258dca677f9d88a7970d4c58cecc20ed1811298a5b37297419ca49c74fe216679dafc938a656cb92bafb78efb31f24e71c2d5b5f994f6dfd82862adfd2faeb8c408fd22aabb852f2bb90f1e2c6274cb1f0195c089766f9efee7d9c86e79a69f557526da555",
         Mac => "9d283d8e8e473a16162d186e96355b1885370e83954dbd08622dbe64f0aac695");
      Test_HMAC_SHA256
        (Key => "6b97478fdafd3a85d0d9b339971a70c2fd24d542abd3e20eb2bd630f67b86668719df258204bf66201ee80acaf",
         Msg => "8b1d4523b6e457f856e5f09875d389eb6587223e53477ba01f49878c6c731ec9f365f28f1cb9c4ebcf89d8648732a6dfa958d2c0152b5e52fae81f69eea26d463e421fba82cdb78f75e5d92304930256a54376a6ea107a995642c45c6f1530a914bdb4ed11a696abf100dc1b147b0518014ff639fc80373ddc605fac1755cdbb",
         Mac => "6ab8f69868b4c87fdec9a031045b34b66660212f687a83d561bc4f9caad59fff");
      Test_HMAC_SHA256
        (Key => "89c77d79de98df18f0cf29a9316d6dc46b61eb7af7f1e2de2f5ca6c525bef3c996338194193fd85b9c6e66a811",
         Msg => "ff8662e9af3a38d3efc0143138fa619a57d569f61e29b3895ae08f2d055befdebc11787c7379d9cd672b5cc25442bafbe804348c78c5df02f30840a114e818f0dbb681783de43ac81b2140bc71c69effd07185cf0eef9f003c60a144d89520a944bda563774103ccf3ece8a9f64fb3aff564854646719b8c1d2fdb9db92cac12",
         Mac => "4746e6f151caf29b3534b2f493f7cc1308fa119116d251481572a1b53a8a1b3a");
      Test_HMAC_SHA256
        (Key => "08cce7d7f3ccea0212cf0299f27f3d3f393a97d3dd71caf1954e67bc8d9a26db5edd7ac23dc7693372ce9b040d",
         Msg => "33ab861f089bac0e5c886f66adc568ae7ba331655a371de7475e269138ff2725f7904c702fdcc62ac703c31d70c29d8a7af451c8ec59342ed397e133da7e76d41b90003635c1338d9f7b5f3c3ce59f3e2f6554c4f064d11f9f5158e199e8463f4ab48aba42d25bff8af92b0b38b7d69241fd20a28fde5e84539473e39dc4fe2f",
         Mac => "2c723282159ceabc5b367b95cd807f249f1dff7f9ebf5ba179a43081454e1b05");
      Test_HMAC_SHA256
        (Key => "1a2e86f6ab2db235e5d7f00cf438680fe5b442dcb1f8c3ae7730b92f097a1a8eaa9be8d216f2576ec3aa321567",
         Msg => "5a2240f64fc704ce9f8ed33d019e4155cb46747a659e3421fe6b42d67f44eb84bdf3dcf1f31e38886f27e85b8b503368df238e1bb511b515bd59fa2c032bddb31d0ddefba97f8f19f7daedea027ef055a52c61d00bb1ec2668c57677e632b180e339ed1c5931310b9d718af34d70a3a4832b96a04fc702db65785ebf12a18c73",
         Mac => "22de07c3055a8935b52bb2c85a9a6b7ffd4038b5db4069c07e9e86ee1b171d25");
      Test_HMAC_SHA256
        (Key => "3270b4e48d575f0312659a6202adbc4e877d69298de4090ed47278b4433fff95802e844fbd73fd4ad5532b9b97",
         Msg => "f407f815a33cd450c0b72a378f00762788f91bc44f09f93de67a41d2222088935b3c1b6a689f935bca13a90b28f64b7ffc28ef278b28271b1a7975a45f4b61fe3657ca5c950b7a2dc2e7fd9ec327b26017a222aba3f29183efd5d33a92d36136eb21acf412c6b14d0efccef849d9d451412e5d587fb060fdcd55029ba401afc2",
         Mac => "dd1a8105ab753d83d90ab39adbc748940fefda05bedea7eeebdbdf54b02d9ae1");
      Test_HMAC_SHA256
        (Key => "c704d5793539ef3909bdaa7c29e9c0a0c441814c37bcd062325f6e2e16107be4a2aa3949cf4d14b0f8f8df283e",
         Msg => "dbb84fef130f929805b0876cb4646a046330bc33ab1cf1e9ca3869573ee1a1549341ab007915dba719b3c4e8a94b62163e6d99dee2cbde2ae74135467b125b417c7544978d50c80c694399db77e878109f59a8335df3a326135a0d50a4bde6fc3e5c03fb7747bf919c68ee8f45c312bc2dfdd279411ba7a5f78dd9bfe16baa4a",
         Mac => "441c7fdaa40e50bf1eba073509769b1c0942f3a16e1e183435819d3b5f8538cd");
      Test_HMAC_SHA256
        (Key => "5b2cced47045bca47512fe226c1f415ef127a209bf885b8a76f5a24f9c6bce61e166bc3ca75471ddc14a001c7b",
         Msg => "1de00288a6e93930070183de9d9ed0ce86f6cc0f64b7bedb5df8af24676fd06fc2e516e5c5e827a7dec07963d5a4b825502d696f9c0ace8baaf6092058e78304f2888f51f9ea4bbb2376c720a2276a61a9f691712d9578abe95f5e69a490e4d2b6b1b7f3c9576e12dd0db63e8f8fac2b9a398a3d9ebe86e3201df726d2d1ba82",
         Mac => "15c62ce7a3bfd5b3b3856d6f47cb19bb7030dc469e35a27807511f81ea83091c");
      Test_HMAC_SHA256
        (Key => "0d4dd35f90f0a10d7d8030e9919446f3d5e2532472bcef0cc5db84bab65c48dc46086f2768d89ef912b8a23d93",
         Msg => "2937aa2ff7c942bf7dcfa670154e988c28177391969db4995804ba1a647acacfd0ca56f63b2e7fbc6965d8f62d066d118c14044c1fd2a224b9d951104a67216f03fa6dbfbb1e5f0f9283b6b7d452c74620c1c2bcc9e637fa7cc8d97623bc81330aef76f1403feba1414fc91bd1daaf132b4737495b7e7c01e9fbd9b3b720f303",
         Mac => "d5596bcc39af2782df1cd9fc8c37a8f96789275422f511280971d8429a8cb661");
      Test_HMAC_SHA256
        (Key => "5ef946b64ff80e4df8ee98a357f07c825c3acc434d0f994069c0b88ccc0ac5e192a469d93f19d9615fd49f6b69",
         Msg => "dfa3b06eb1e30b47ad9f0bf0f441fcd94856ca8b1f4cb88cf6795582e860ad9c7f30bc2eca8e289bb0942f78831addeed934836097fb664e4e91b47acb5fbc49e9a15d6baa25bfbe864f42700361b46586f9c7d869dcc2444df17685b291743ac5fe7d6f78303a79d8d82d209c9fe804f9ae7d39be7435359ca385ecc57c3d39",
         Mac => "223dfaf583140a769c805c33f1f30bfb2f0926b088f55439dfeb4f5a9ceeedf1");
      Test_HMAC_SHA256
        (Key => "79f87734c46c5a11d86aedead22ed3ea01577ad4ecdf42969650e12000350676f0cf3c04f10a11339baf783914db6d35d7b0d77bb44ab22c18f56d0b8f9d918b",
         Msg => "509a0a45a1512b5072474b297f9c1a8c24890016144468504e245fe94d065d437fef6232f9f34500695549b44ceff29361d417e85d353701e081117aa8d06ebe058242ca8c23f3341092f96cce63a743e88148a915186ebb96b287fd6ca0b1e3c89bd097c3abddf64f4881db6dbfe2a1a1d8bde3a3b6b58658feeafa003ccebc",
         Mac => "b5b0c43028e81628dce82517fa36aa29");
      Test_HMAC_SHA256
        (Key => "eae255d9e083268f896429ce36645502aff9dbeaca7159f93c7d51fdaeefdbfe14c396693a5ce46e9f1157a687e866f94ca165bff5f7b425092236d2a6a004cb",
         Msg => "c28f6a09ce076ef270458967fe19d46e6f6b2cbeb6362bdc4fd55684177e984a600cf0814501665c3bcb4353e94681c83a8381ebb0c8fcdbfbd73c0eca738cf2e121edd46b2c0a0292eb6e2c4e46f5107a7780572d0eedb9473847684a4039ac6c56c9caea90432b9e2e72bad422168e5ad093c9d612e7c05c7fde5c40ed89c0",
         Mac => "b84003c417a472fd2935341962744330");
      Test_HMAC_SHA256
        (Key => "42521bc3f168b2b3434cb4e44d92f526b41c5f10bfe0a0e6b0eb20c055a636e9da599b86e1ed1f78d4f69a837af126afc9c98beefca1fb00e5cd00948321b2b0",
         Msg => "5a600c468ec22e42af5ba93eb79452864ebe469a86f83632c85201800f3288b553f7bec649ddfe704920a27a8f65d13aa755985a238b3cdc8fb0cf5ca7e40295c7603a27a25ae69837290f9801aa30896ee2493e93e52f031ef626de8cefb1159ce4a9f003038dc061be1920742d1a7b8bad80cf3eceb5b05d6c2d8f261b3f3c",
         Mac => "e1c3c6d90820511c8d685c73bb757ee2");
      Test_HMAC_SHA256
        (Key => "81b5f12a64f3c347902549a1fabd39ea1d9efeabed3851880df40dc541d23f0926507d62218f7a8a95b1d76959853bda6966a5b2db6001ff1595fa8d3edf10af",
         Msg => "04369f9592b00626d15b0a4b0ee2f92ba0d086c16d016ce7b05654b4f9adf90875118a656f2d50011707901982ebb387f3a4a49759f37a17183957ad0c778f6ecb780dab2b4df30e05fa81e6386f38c0f0ba3f37287a050d6d97287ae53096c391d5f20fcff73977239ca55c3657d1fd1f781f48e28057f136d890c28cc25432",
         Mac => "5f840796e0d35c807b3d715727432e68");
      Test_HMAC_SHA256
        (Key => "34f5d28d58364da4b95a48c07e01b0a99c5ace173ff2c9216bc96df8e3ab2ad54abd60308857da336f11986e9f21d1cca6e438c66cba7fd6cf17192f8ad745ab",
         Msg => "59a6b0317f130f6248e746e396cc684b32b9a0eabf15c50bec1f2f76ee8dc9392e7368a83e675ba312e344176deb26c799efbe4d5bf2175b26ec59478f6de1c7018497f9b2df7ca6d53383c712dfa24833cc280d209751330df21898f2474c9d3b9fe62ac1c39af3faa0acfa6cf0055568178632f44b9c1809f81570ff633243",
         Mac => "5a33b8f7cdba999ed61fab3869b8f1e9");
      Test_HMAC_SHA256
        (Key => "cec8280c87170f1d4836cdd77abb2a34410b8d5351d96d1a03e90920a71a59ca1ca344b49f9d1352e1c226d75c74e555e601fa268725be8c88d0f094cc2aad40",
         Msg => "952e93853e9579c2fe353dc83203d34f04963fd64880a095a4de6eb4f42e00baec615148ff31030780b5a4df0833316a1735d8a8fedf02f4fc7f9136a766665b8df727021cfd3f78bf4226e74a5de2ca98cbcea472419af2b341935eaaec2435c0179d1b5ba034fe02024a48c128ef59cf7fa7346e4f6e78134bfb93c7674232",
         Mac => "aedb7ea80734d1a65723da4f3ba18f86");
      Test_HMAC_SHA256
        (Key => "9f65a426106db99dcb2130be14839241d4a92c8becc108d2c9521b8238c5c0df7c2365ec9f20848c0559d6e847dac3103ee31ce55dec0c3644e64c2993c497dd",
         Msg => "7d3d9286c1fa057175c33c556d2c4b87fe46d1b764727d6b6172d1ac27c626fe7835f1960caa44c8334198bfbba2c970148e62d0b2b71b45b3d5a05bc2f694b93b15d6538fef03e1eb123c8f143729f696d13d4b1de63cd6231efba6cb1a68840d06c925147249a4e45db02f40937200cb3aeb8e6da7e905f8766bf40cd9a846",
         Mac => "9f19ab5e517e884cc1b1d3124ec9ca50");
      Test_HMAC_SHA256
        (Key => "2edc66bcca9f99ee1366992fd0f0f954d3d4c5ca2115c2d053f6f8e33c0f6e7acca135f43427a7cf4b2df11a3165cf2d32f89797ed1a7958b5e105513757edf8",
         Msg => "188a7fb0222c9d8e19d057ab22d71e0356c4f8d1184179aea663eefcef2edb85a55ca860925a97152f94f90073f2a2fbe9a29a370519156bb854a5314264afac48291c6f265e509a86d5604632047f2426c1ba60ea4ae6cc1e88d63a5695d129297b42a5853fb268451ef44506169fc736a8c2156dddd2180187e7e0d5c92844",
         Mac => "03243d10c48609e8f4182638c23516a2");
      Test_HMAC_SHA256
        (Key => "f987eb83a3fd6d94ebf3626b7d34fec23ee06c63dfb4078cb38bcc97bd250fda0e286ecd4e64046a985bdfda8b01b34d9dc0cf2ab3bf5168ef64963bc918f5f4",
         Msg => "e105ff11481159c52baef5de550898214e1d9a90da2d9083c36b29fad8f956323613ae76c68b103807758a600e2379e4cb54f2998da86149c857700517232bbc7d8b610df0424d5a18df751e54d6d380fea73328f055dc51461a721f66591b333ed4e17ecd1f5852e55580bf2f09ec1c6f7f24e4091c49c4c51cf7f1cf836fbf",
         Mac => "03364863690c439b306a2967daa2418c");
      Test_HMAC_SHA256
        (Key => "5a35a2909aadd278b810b101ed44e1548ddaf9ba8c882bb142d9243f6b23348672baaf99ef63938e6e0b6ad472b972c7b9c2fc82c23c12f48db45c37a224451c",
         Msg => "ba527305604ef5581850b222fd192e6260c3f20eb30d8f04a5f4e1438f83915b0febdd22f2d69ca958f97c6e12e88fd34f2f06cf789e3ce458e4f6518060e988ea337ce2dc9ad0920f7bfdd8113d9f77e8dd9268f83ef9d027c185303e16f4db9252d7aee54199fb87fdbdc6c0bf673473f61e40fb96d0b059b31647914eba3d",
         Mac => "d360c381d230d21cf828782ae5e389f1");
      Test_HMAC_SHA256
        (Key => "96da746779ee441651fb9ccd2da621eff4091111f8fb795cce92a8335ee7e31636195ac724955bab0394c672d5e5c1fb12ecac7140eb58bbc4807313f86f47f4",
         Msg => "198b79d09a3dfdb5d41043e679baba6592f3c751cd7cbb0d1860029f6e7a9c56f137d2b03a9d217aed8c7b399044afc99d282544d5c2ce26d8065baef3dbad8739d78da7d54a9e789e7f8f35ec3e9597aa9519b2add9ae1944e7454911afa44517f4147d134d5af41070e9a236af5618e3c30c62fdc94131868a293a70ff69d9",
         Mac => "3df86c710d782309023d65fccdb91db4");
      Test_HMAC_SHA256
        (Key => "43aae2621459a8d5b5cc919445f3dabc0165d136ba01e58187d5ffb2b73f15b90951fce5207a7dab3163aca3ff1875d309687830018e17628111ccc8fae8c0bc",
         Msg => "bac0889281fe55dae17c45079bc44f8976508f5a92953c26f940daae77bfb16eac037d7d5f8467b615863415e29bbd63806a9f169eae33737a82c1f5b2dbf0f25856817c44343d86aea22c47fc3e08e4d8d8f14986756257749a644513c70240e641fc55d914c091d35995678eb51a51a722efbaf1f2b21c0f112d66428acda0",
         Mac => "83467cdf51f59916b492c5aba554c606");
      Test_HMAC_SHA256
        (Key => "fa235ef9f48a666e2e55dbc448ef934de0d22ef5c0ecedc75548c8b364eaba8ef8fb605a9f26c2c8d54171fbc130d28f1f06b9da7e6e3971ab4abbee6d994ef1",
         Msg => "da32314c22dde556d886ce2dde1291f1a4c1ba14aaa95b694063f57e91049c2cdf4e576c1028c66c6a4c07e39b40d9a1fc87026a1618ef04660f9b8f5da3b215ab58f562bd75e01684b98af8794ace8ddeeea8ea467de1c65797efd3cf92174fc5b6d4d532ad7c7aaf3521158018b5ded25e723b41c179d69d61baf3eeb91301",
         Mac => "0d88a7f3a8369888b4c3223499412256");
      Test_HMAC_SHA256
        (Key => "bf248c7c6101e6e0281c8955e5cc028d98e5688d3f36d754f05620bd26a1bfa6597d0e52d1e2b80cbb196f0d7dc3e2a0471ee984ea840392ee34039fde5506a4",
         Msg => "557f845dc8962ae11561f63ff9f7a9fd73ad5da479f1d1c3e9760236c292fba894e4ed5735398217b6b06f9a951d49ee34ac99478ac732ff1939c2db2093a89011ce0586453316dbef78c1ab4f2c6d8f285517637357a24d55176ffa4f612e2bb587f471614b8d34a8ff13fa8debbfe635ef007f9b6acab4855a311cb7c43682",
         Mac => "84ac389ad6e42798a97784941bb76fa4");
      Test_HMAC_SHA256
        (Key => "8b4c9c2783240e19128fcc2754c47d68d6acb3365999cd85d3351c74b7b94422765fe5c346197bf3228383491216e030ac9f7cf2dbf03216dfd6ecec954b0866",
         Msg => "dac416df793ee5fbca992682974a0c2cca63eb49805df0a75e1410b628133eea8f12e1614bbd85c66ab7d075e8dfb8df7fd2f430c0b1b03063248567dc9ea8852fe3620104c8c0fffe3a8b7749827a9472c7a75a7cd5408c301d7fcdb4fcdc055f408106cce8fe702d2b3ed1e2bcb9114b4dec0eda5206836c07e52ed9b44032",
         Mac => "fc38c3bddbc320bf7373834f3c83ac67");
      Test_HMAC_SHA256
        (Key => "a5fd99ca57c1fec8159a798792426d296fa1b17d539241de3dea335819b7ed0d92c596d72867ca2f8273924e058f9391a5ab8522fbcfe7d59817f1509afccb6f",
         Msg => "5cf3a5202df8706f6bff5bf2590de37c902c7ffd4e6c8ea611288e4e658a8e15fa51e647f9d22583983d4b1ced2239bfff346556234cd22d86b140530696a04446e4cac4013a720e9e32582e05e7c0acb2b4226a073e22cfe7b4c2258055d7406833ba61ec373f5aa566ebf24c62618ace341e01a34866d65cb97e8c7cd01c53",
         Mac => "2c2bc8c87017f204c958abd9aab2beb6ac67781d8d9d804c");
      Test_HMAC_SHA256
        (Key => "30bc3e321a8978e235fa1b550064b82eaa0c107525eacc827cad6f1d66ff88e31b092cec663aa3aafc4462140c68390417f4cede020a4a736aa2522537d2394b",
         Msg => "c1263be423e7888eaceccfef26f0b5aaefe03f3ce732dde98c78a7f66435e6199cefd62eee85aa2bc8c3d156aa3478b6cf3750c71155917207d23f3b7082acbdd4de3e536857721933eb21136ff502ab324971614d806ebe7491e989a0a23d3eb21dfabc5905e73e358b478c3ddc5c735e3e2a72645b7db61edc2d49bd3aa186",
         Mac => "d722b57c48128b37ba38770cbf4660697757bab95c00c484");
      Test_HMAC_SHA256
        (Key => "c189ce5334f670ed2815607ba9549f07682e11f70259dee3854019a431b3a0ad7bdd439f58772817b73c6dca4f9d10d59cb50c4e247fc51fff47a614965e0932",
         Msg => "a5deb712fc3bb9fbaf1398698b5696600fcd61ac68489f26a0f8ca32121a3e8c21d5904529662208b67af4a2f4dbbdc1674f3bfcdcbec714a0922c7aef63b911afd495345fb853fb4a7ac6ba00bb17cb063c148ecdffcbade1a958a5632bfb82b9a16ee9847a755cd2dab6ba963ccb05555c96682154d479cb05f5bb55b82c67",
         Mac => "3d6305ad9dcb3a50105b92f331009a3cb03ca7ec36882fcc");
      Test_HMAC_SHA256
        (Key => "085ecb69492deaa704e25aeeabb7b7795fdcc807b3255f2fb30081f425a9c7990ea104b7785c288c733965965ab8906057e8c99d291e5e7325eced197b51c9a4",
         Msg => "2dac1599844d82a79c7cd1669a1c6976267f655167872f8b2e0c5059717e8651fccc1770638466613b3bc4fc892f880e7b2b625856abecdab0418251df3754feb176b9a95ea6c7e6ba972097afe00eb2ebc6d344d65f3ab6c7f7724f77b21cfbb673a34b5cfdccbc83588e3cf37723eade175f1eceea41a9dbf5c85e213607d1",
         Mac => "35fa859b3e4a793b2329652cc61f9f68816fed67fa402e1b");
      Test_HMAC_SHA256
        (Key => "f5a07e3741f03174c6efcb1f9f186d1f233b367073c56e814f4204db2e203b048db6a0a387853fe4a6bd161ef903cab46671993942de90d71f60fef1e5102807",
         Msg => "067ef2ee1e95ca546882e2a9d441dc563235198efeb52be97dc7894f092b8718a89c8571e4526602d7cb44ce86cb615a70a2611166adb7e79c1f5e3d0101c904cc781c2657479c21319464f56fef5b41429062a9cfe0d27a3a3c259104f5f379989b21d3207b55fb9d66ace837b4b054d189841de15762ec7fa44814bc0eedbd",
         Mac => "aaed7dbe184423f0b4c9ff72dcf4557ec123b49682fc24c3");
      Test_HMAC_SHA256
        (Key => "887c37f1f09920ba51885934af50a4b065e9e2160e971ed8a676cd26ed5554610cc7cbd17b78019a22bec0ecbf70527b87fb432f10b2691c6e6622b49d37dd3b",
         Msg => "d6fc8b4b72b7eea80b1c6f53c11a52510f920527feb8f95598bdb120a0ab1994809018ca83de68674412a6656794a51686de08656ee110608ca4b2f3a22fedf6bea75a6b6dba05002c3e7bdc1f1424970653d38a6ca29c4a21e6e66feb1ec09a798a79b698136a7daae7173e536477de75378f1e5fc5461b41ca741be33f3c86",
         Mac => "51ac4d2b5923a5df8ec48c14ec514a0629f8e385a9ea4985");
      Test_HMAC_SHA256
        (Key => "e9061ef9b298e47af4bfe35903d22e2ea4cedb85c53e5ae16b5e0501eb7ff7615dad22044e909c71b5903afc283c604650ed17079ba6600b303fc97b28c33d5e",
         Msg => "5e873df5f280723dadd718875684592a7b2c56916646bd874d7c99b1c9546f5c890f867a48d286e6fc0345f051f6dd1555c9020e758c920da8a56e43ea7389a5ec323ef00a1fe7ea7ddcabebd215979d9a64f0006472c8b1e860d06b85656dceeeb80e5f20b0bcd19729f383c12bb049b3c6cb6f1b4087fb757368338270445f",
         Mac => "20dc2be5c7f0b2fa8eaf026c152a09cadbdb82e52538b393");
      Test_HMAC_SHA256
        (Key => "78bab2c40d60d0770c5d2bafc455265942b0d932174afe255b6c0ed4f1fca7750df031dff408c1e403bd3de2f375c2955bf8422f762772ab27ece35e3a6d6ecf",
         Msg => "c2925d3d09cfab81f32f769d61dad5a03aec0423be785a7417cd7bf331f7cfbbcc893385d09aeecae00ee628311714079dfa357cf317c26e922423f736b9200c111198611e0f7587b27fdf57549fb094cedd28cc84e3e37f05d10784e0c9c2a7b9b1f4979b342800900ac9f46f7a938ff61d47db18e4a3f1985c9161d7319fd4",
         Mac => "da713e318a9e5b4b4f1dfe0a2af0837d70fde54442f264ff");
      Test_HMAC_SHA256
        (Key => "a2f1635f239f03be853b26aee7b8035a5f267bf0ebd7a8ebabc0b8984d21fcd3c8693c124d544ea67a56e63dd23cb0aa6a119ce9e43e7a5da1f6c65d33d1c5ef",
         Msg => "5c32698a0a56b9aabd41270ec1e475c5f965bdd07366a7843f8adf2f8235c7fec694691e94deaf2245d9d6a5159f203079a2c95eb3ee3d3da3ae88f8e0f20eb307af7cb75307fecf6ecbb3f1873f5e21a51d5e933bdce010fc31539af0d71c53c88c8b9b6f5c0e79e121a53c404b966225dd62b834b8f7c3f31c275fdc6c59a6",
         Mac => "5ebf7b7d25b0ff498322e4264bda56f7512e9d4ce3c9d51e");
      Test_HMAC_SHA256
        (Key => "69f533836771a3cc0087fc2fce7c42318f24c76acbf8f139b8693db65a7484e8ee777e3989438426fd729a3bfcfbac3f800318ac69f66d6268d7729b1dd46b22",
         Msg => "70901c61c43a67e647b5274e55fd3a934b0b8790eba58470027afc67476e0fa087337a76ff1918e60a27a944fc6ad32e4d8d66bffaaae404286041b40a26e71b06defd5813aee9c8660b13c24d16ec855b2c306ec5b8686f0c4cb2bcdcf1c4c735bb2f6fc8a0e174a489ee2f11aa9080bc0f6c0715781697f667d8e78577af8b",
         Mac => "4f0a78dbbe767218eaeac0400656c4b4b23f908a9e7f4708");
      Test_HMAC_SHA256
        (Key => "2daf08cdc015bf361f66be9cfcdd6aa7f1003db66fc95e23f70475c88cf8bdc268495b74ee1deecfe07e67d1d2001b4cdea316e99afab26c478d693a4b7de818",
         Msg => "a85ee973c99d8da60d745894990b24b9cad7e450be0e4369175e883bfbdebdbb5f45106e865a797bc4ab9d048882f3b69a15259fa0fdb940e7e9f0e46094ee30e9f41cfaceb5cb5f90e51a0fe5f119ecffd02ed4117eb8ba10acf3fcb7b61cf0cdd5d5c0aa96ca79f88a955eb73fdf828370c8961a7989ff190d582c062b8d26",
         Mac => "e6e7baded94fd4042c2d3ccb586d8ca983e8033e4ccffc68");
      Test_HMAC_SHA256
        (Key => "65e35c88ebfc4c425d0362c5cd125ba40a0aa76516347840da281a2419ee82fba364292fcbdf1b6d1a154aa9453b29625d6a76274647575a6ae3a934aee09509",
         Msg => "7ba8ff928460a47c78aa938519d33978d7172ba2975c0d2bb421b2a643b184e69c9c2713166759fe11831db23a7c184c0a733b0c90cea2ab712ebcef2da1ad7ea31af0f0d81e4127f4bfbae38dce3c91284d1064fd23cea7fb137e520ceffedb9a09a44e52eb23a02848b3419b326cf03a8cf3d367c359c75bb940f56a0240a6",
         Mac => "d9eafa06a75b5b671be1b1f1e6296f17f71ff467417b7837");
      Test_HMAC_SHA256
        (Key => "84d5824f5b0deb22f4476578e8d0dd192bdb87f93019236a54897e9079923b15f14fd31f9f2adb7f58ac862c8f936aef3225875fcfc58510fbc43d08f4797b72",
         Msg => "20dfbdc107b5e0af83b2d16021039d0269de2d27b40bbe6c3ea492597c19e589b076230bbae95807317fe8a5b22e802a78184c652d0e6b490053a0dbf8a34a4f8874966d637cf33a9173c6d5c31a5f9fe47c2c9ef0742d24096fa8abc8731e04d1617db1aa77978fcd18d3b8fbd023a7d493369da545ee448180149293914bf1",
         Mac => "e7928a55a3e4274394d81988a08196e07d5a5df047140690");
      Test_HMAC_SHA256
        (Key => "833b09f3a7e41110f35ae33acef5c9a76ea93119548154fb154815ac60892c1b3dbb839493b5e0d9ed68c5757dcc954d621bf778263e7f508b848cc9879a6c02",
         Msg => "62d432e97b1214a94ab922b6bfc7f0a32f0e9973a737b0b67f067af532e05a506d8a8c66653316756eb5fcc2ca18b43cbe57d95ceb67244fdc769757dc71fb6f0ac88d2eaf75f5edce3b772cfd2b6d32746df5f4643de7388a340afa03c9870f62179d0800e1975993d3fbbb020a05ce78d75303b8c0e2b9b0c839a650f1e479",
         Mac => "b4c5612cb1c1dc4333450daae500cdbcfe3ee1e3ef7a0d61");
      Test_HMAC_SHA256
        (Key => "5efd2d24a034c9cb778e6730c3739a2e48abdfdb0e2c2203073083d5f38b59db813c7730b742afed93b195e4f3048591b2b5e84d140bb2c564342fabdb9300ab",
         Msg => "b08f5e5926b68f1c18652c7f7fc593fb3c3f5370fed6331965bb77be681b5e2bf43cefe2d5c8f50dda6949b634954f3a20acc3fbc640b65660b3d3d59e08e7a549f3a14a28329691202087c69e88e7283ab7989a94d5f69b827516786e6a4fc0f9dcfaf9e49c779131b57118854462acd18959b4313dfbd11526c7119eea9f66",
         Mac => "3d0a38dfe4a8801ab9f9dc1446c535d792393ea8d763db4d");
      Test_HMAC_SHA256
        (Key => "992868504d2564c4fb47bcbd4ae482d8fb0e8e56d7b81864e61986a0e25682daeb5b50177c095edc9e971da95c3210c376e723365ac33d1b4f391817f4c35124",
         Msg => "ed4f269a8851eb3154771516b27228155200778049b2dc1963f3ac32ba46ea1387cfbb9c39151a2cc406cdc13c3c9860a27eb0b7fe8a7201ad11552afd041e33f70e53d97c62f17194b66117028fa9071cc0e04bd92de4972cd54f719010a694e414d4977abed7ca6b90ba612df6c3d467cded85032598a48546804f9cf2ecfe",
         Mac => "2f8321f416b9bb249f113b13fc12d70e1668dc332839c10daa5717896cb70ddf");
      Test_HMAC_SHA256
        (Key => "ceab398e4107483ede64ce107c9270e6022778b61f6a258d3b7045d4ad8506d32ece0a738d2cb948a562dbce8d7b66f30e6694d65ae439cffaa454af09abe449",
         Msg => "6dde9ae867e2feb367008a975d7853ed8f89690f3c87a1107f2e98aa7736f477a527ed64956f0d64c1b23361b261de78688ea865fcff113c84817e5b377e829cd2d25bcf3adbc06762cfda736f5390d01a49079d56e969f03313e6c703e3f942bb87ed0f9c4d9f25120085b5dc75ef5d6d618da0926d3293568dd7d8238de3d0",
         Mac => "2d3a760595f3fb19293cc6d23651222a9f5a4f02284457a9c1ed4c43ac993ca5");
      Test_HMAC_SHA256
        (Key => "6a6155dc4d59c6bf46caa3de09666326da308c51a23e6ec342bd12b227376e8a1f11da906b58c8c515bdaf0d84dd48904dc6fd614cb79f5ef4285757e30adf72",
         Msg => "107bdfb55c601e74f6505015a5cb87bc0eb0b2e7cb04594fbeef8e0fa5072007eed21183cc854a188a128ecf2062ad8604dffa924236fea9cf5b6e001acd5bb0e51ba95e53a7c21b42aa8b89da78983f66069c6f63a923c6d7208394e5d50f2d9d608f8f194ded45c51f318bfe94afb2df2b7fc657e42e6f7f47b3152ba7a547",
         Mac => "6dc2b05619ad5458ee3de70b0c1649b3788e1a5312e8924b5486905506970881");
      Test_HMAC_SHA256
        (Key => "ce97ded47e101a6d0aa1041138093586046524f54345ec9e860550c9415bfc002d2c0d7beaa4d4dce985d71d89bf19c680429c637d1023350c963c28b93c7e05",
         Msg => "f62796faaa333dddae596f98cd4de3931ed90710287446604a158b575b4901fd8d841e8697b4df85131c555c246060f75ddcbbbade3a38b7c0444d25b4f6d00de6d8ff47288bc3a54ca1366ed1b2620ec3ab4c0bdc6a313bef880f3587766705cbcc4124a4dd72a7228f1ab61c6a704017eec2ed692ab7549f8ad86f1bf14e4b",
         Mac => "837ecd647e03fe8df9a92c32dcbc87d0734851ffbc17376e03218cce9cbe974f");
      Test_HMAC_SHA256
        (Key => "554e344537a09659920c19b40f2850b07235c3c7209993a6de905c82db1e5faff148e16f2883ce087c6da219e0bb892d8272c591515b5163bdb0c4ecbd1c7730",
         Msg => "44e9a1f1437791963c1a3e0aaaae24affc3b405844d16a5233b6e5a145c4358b390c305bc4bf585f864f68333dd12d4139a69789105a109e92cc0cf1ff8fe2527891dab4b4fa8731f457574e39f8687fb4969dee7e3af27889590cf8d74415c9e9c0c6867bf0c5146e7c32e306ec7c7055557a0ff738b7e700a70d3e33a975f7",
         Mac => "9cd24a0efa26c107738f5335526b57d8c93e54fef8c1babbbbb2d42f3a1d03c6");
      Test_HMAC_SHA256
        (Key => "76d8e0342011d2bca953b26ee200e56685b721d50ed4dda7cd3a05633a50f153884998e67da901528004fb7df4090e1ec4c0b11f3f10bd4727842215044fd9ef",
         Msg => "0ebaefd2153de2c70537ceb27e5ee70105ae85bd4da38462b4abebed11dbcd36ade16d808f3aa54ffda5897a3fd74780a670521fcd2ebf231f60ef7d999e6e94d1b81be038ec89b49c5ca65bf1bf9a675056f2464021fe16355477ba5605652e8327401797bb569fea456c7f1b7da85d0c48af592de60ae3fe6dcecfcf767cab",
         Mac => "1cbd4f923d683ca38aca6cd0ad81151062fd642b155b2a950eb551ca8216b0ca");
      Test_HMAC_SHA256
        (Key => "731ec9f365f28f1cb9c4ebcf89d8648732a6dfa958d2c0152b5e52fae81f69eea26d463e421fba82cdb78f75e5d92304930256a54376a6ea107a995642c45c6f",
         Msg => "d98557504a21fc3a434c780c328ec239cf8d7c26f58d6ad7b23329c79a8e1e176058aceba778aa1215cc14e5a92600714f94d4d8b2e5b7f45268453ed6f787eea3342264ad13cec78d990aecd5e30f79a069024a6d846d132d2ef0479a093439cba4218205f951a2d53ac4ea5bcdd599e9956c45cd73767c6a0c92ac8ecd0d40",
         Mac => "4f2501d2a88cb13046a6549f90e4ea924773408bb684025b5126a8fc21f48670");
      Test_HMAC_SHA256
        (Key => "cc38826523a9097e0f7d075a3a039a70ca1e2b5590a6443e820ba1c16c3b89dbe2c65f37794074ad37e81f0a4786100ff19ae1bccab2eece281c6786d9bda3ac",
         Msg => "6e09febed308baa41a8b6e0f7fab61808c9c8471ea32eef178a4888e9a910a77d44026e2972c02ac5ac0ec3fed5f4ab90aa7cf4b2ef7f5dea62ea7fdedb63def35c2ae2344d301d2818105df4f78420299c12f25ae43a60e5089943f07c5f51abc15004982069e5db75721b54cff33a261700cc8151ee9c89c3bb91c92c51942",
         Mac => "83b1403389173568588e5b6b8cf9da180408c79f91d054ac5cd99de0b728ff66");
      Test_HMAC_SHA256
        (Key => "62c1d149567f05a0b76c4fd32d1f365d170cb165cfb38f922f1716225472eb36a127327007f8f5c08479ca7beac4b0aee26f3bb130bbf1ff390ef344c2a4e0b8",
         Msg => "7af390cc4edde0f3d496137d0cacd0876b54c909dc5ce36705619742cb42989418d4b6fcdbd80256512a338f843b48b711c06f582dac2607ea5ca038b7126a5726a54e14f37778fe41a6d7532687c6166a50ec638c14600006f51134d29566dc2dcd21bb9ba289122b74c870fc7992cc006a07d1007cdb79e192b4dd25b1d34c",
         Mac => "2f1a4c2bde7c8bdd7d8a9b6315b19ac654266120c652fc24ab19e00ac11c5461");
      Test_HMAC_SHA256
        (Key => "af81e327525f3a9104b7282959a0f6600fad7efae7709bb8b33cde34b12f830c1770a342efb6abe3250a0ce7dfcd34590cfcbeb840b3e59cbff03f9cd89aa870",
         Msg => "75ed3ae9085bbf2d034b864d7f87057c2d0b12c7395feb0375237903b3ebd60e724e0c8fbe3a200f518a4f61fedb971c509b794f6e62fe6f4186f894d9ea8ae50d16ea51628d66812f5aa50afeed30e634253025f5ae7ae0428dc86f64f949db8e6d5d96befb996ae4e312b04664d8c223d2c0b396e9673dbe6173fa1cc21cd7",
         Mac => "579d35cef5b6f8468c8285829861e93587c8dee5791208406a7f4bfafb70abfd");
      Test_HMAC_SHA256
        (Key => "17a5baecf916634433dcf133ddc2dcdfcf4a680e088928985138c01d1d09eef3b437cc6290614f14079814c72bb75c45eff255968bb29b7421a1feffa00086b2",
         Msg => "7809e59ad48aeb2c6f03de775b1371b7f86926ae0b87098e10c69e19d29b18073818cba862b6e4caf45158ddb2741a554ed791507d2649795004e92cc25065db8ea774b0432a457399816daf062025108dc8b210d75124d284a8434ec314c7af20bdc7f99e6e74ef069a07347e9df8b05d4571353e91026354b896c9fd6da64c",
         Mac => "810d7bda3421589a7dd60597447edf2b987f1e7283f3c65890248712c80969c1");
      Test_HMAC_SHA256
        (Key => "e09ad7d2ff8d559a26e0454bcbfff844e8d2415b07872bc59c93e73698f308483bb8f3212ac29050c1cc46f9aaa92732afcc67accc0e139689acffbe878f01fa",
         Msg => "4745100cec0406cffa146350ee12213330d192123af4a1bafdbc5c98801eaf6ecb19724a0346a7b9d6b1fc381ae798ebb0501392afbfc6b8be48462dc2522bb7baec1605e665f2e42f1679b6c383fa1f00a35a01937b5aabe1f2174da6e0d7afdb680223de886fb9cdeee1b1320dd236e6716f492f4fe3fb2c61d8df73f03bbf",
         Mac => "055ee0ade716231bcaa0a7d18161004127a37e7aa12773433a376073474d3d58");
      Test_HMAC_SHA256
        (Key => "fd013d615c6ca959030a520e148808a07e27d38a215634d53486ae8be43a856f3e5dc6eb4fd9874a8a6570276a9e7b25585af7e1ce39d325bd7d195f2c1bb951",
         Msg => "91ea78334108ce6261ddee5d98045bb307a6e8f3d0ee65c1d9bc7d28cd9edf3264fc9cb6e592d072e9238559616cd42eda584d5200729adb619f5ee5740d632dda67f5dce34b89a054fda301685df6f31416cca78f19a8a7124a2a22dd7834847a934b4a451940152cd20ffdb4bd07273c4a2b9a86c9d94e7323a9860ec89860",
         Mac => "eb5aaa4ee702ff7b5324bc72c98fe87df6d9cc342b053ebce6cbf27fdea0eabf");
      Test_HMAC_SHA256
        (Key => "62e3a735edcd87fca0dd1d2797cc0e574160da9ac23f60e39501a5b77688d1287f947a0791922556f5b50afc434818bc83433968931cd752c9df9f04d8818531",
         Msg => "ec638734d336b8da6dfaf3da9e18c7131494fcc0709cd3a9a6618e9ba62533153c958e44345a7531c3eb503a22a5d8bf7c1d1e1d0ab5cfe07d6db7349cfc859d2e20cee81a325462cdfd8747dcd04c7dead2fe82cd96b2a4ecefc070eb067f6c8ba94f09cbe6ddd354d9a2eb13c2adb7285aa3d8ff68045cbc8faf35dd6aa9ea",
         Mac => "26db47a48a10b9b0b697b793f5c0231aa35fe192c9d063d7b03a55e3c302850a");
      Test_HMAC_SHA256
        (Key => "abc9ccdfbd92b6919a5d6c6b5a765a39662ed90080d3549204dfaa5f6d70d48e1af8c84d53369d658765ef11d7b38510d9f431f99598f8cfd4da73d59b3b75a3",
         Msg => "ac4756b851fc8866b9adfac2d02599148e0db7757a62b1e06d26cf8c99556b79c91a5649ea437752cbf3b5f121961821ce1a2a4c635da461e3e14626cac707d04dfb6ed1e4ac40f106ff5ba03304e28a38e99a6daf6d9427c5980d1440a99296c05168f5441e2a6af13ab4760f55407855e0cf7f667ccb5d9bb2eafd03e455f6",
         Mac => "0e445d77789a6947da70848dc4da5dc9c125869bb6945b04304bde93829a75d9");
      Test_HMAC_SHA256
        (Key => "07c358ed1df3b06d47b5ec763afa07a6677ca3a722524e6103c1056d8c56f6cd0d318adbc5a4a3804afd23a62b9fadf0d358afa8b0eea0f995fb865e5dfbbc5ad2a4f26acd76",
         Msg => "2aa1d94ec83ce7c3c75c6bc847759b085234fd44b407d8f80ddfe93c243556e87e4be8fb30b4743ef1169a24732fb2f5f416042b10c3371dd9d20dda29844d58370700ce69f7df5e69240df77b96027a0ecec71b904f690b875da854de05ef047c5d898d1c0d116c580e2a0906b271dec8e5b0dcdfb2550a40092270eabf2533",
         Mac => "b3a189a17e8d9e986cd31bbe01b49fb3");
      Test_HMAC_SHA256
        (Key => "ab8dfba4414e6986513a9767af5eaed9720811c4b38040b991f3fd8278b0adfea497002ce0cdd48594b5578ffe1c6cafc0b4513e9bc47ee07a1dd011b250e601881ecca2f430",
         Msg => "d1a7086d134c11a8a3204e019f52843e89f2d01a02a88a94d4a66e8d36dbfe924c6922f7ee5a1225aa8e75340cf8cbbd1c0b08e9296e81cec5f70cfc11d763523b12ca174433f246073d1c2877e4812828fdf2e41134bc8090fdce3faecd1e54a58948f59f3f78b2c1148b05687d712ab2b2d630416001513b9efc7f9523f53f",
         Mac => "7aea0e2d93e9a6a3004117ad4a4a72a3");
      Test_HMAC_SHA256
        (Key => "fc68be1e46a7ed0d4293c6ebab8d7546a7b6e95d495f7d315ac1d8df59ee112cc008176289b1515bf1c281db7c40ee23398cc2c247d9b1af98e3db95f5dff46e42ada2530455",
         Msg => "eefa0d62254597bd67c87e00fb35f69c5cb2dc09f58d9d14292b547b964232b79b482319172cae1874431deae585df51ebf92ab81e6ee57e2a6cc492186ab540cf417b4adae1983b6b4371f8a09fad9806dede755c52638399a58de1300f00ae92cc5c1ef4ce1dcd53afc053b6e92818b4493f6a35a1e0cc7dbef5916699dcaa",
         Mac => "04c8f6ebcbf13fdd2ab1e5c5c25bc7ec");
      Test_HMAC_SHA256
        (Key => "6e9ce34b4fbc78ea92d3d14592e1c0725bd053d70f4c599b89d4215a3f11851d6d67278970cbfb566fd40603411465c88ba890cd290ee099d0374fcdf1dd8012e017ff50352b",
         Msg => "56dc2b84da28f94847f598980ebc2d5892274e1639d0b7ecc24c3ea8d968092be8b2fe0f313c7b8d1a9c479dc737c95eeec078b9e7fb934103c7125e1f5bdcab79d03a9cc2e08c6474ed3b166544ee0a9da4018264fa338da06f9e2c5ea4edb4af3cc973b59c9496fdee5a4a0f6c042244dbcfb9d855fd98404ccb5abecca20e",
         Mac => "c7e82b7b2478c319194fed944fb7c772");
      Test_HMAC_SHA256
        (Key => "91e87e19a4a4af9b2068f842e624da9a21e57c40cc4d4df57541ebf140e144792ebdfbb49f450dbb1682b4ef3d048b8f291cf38ade4bb69116f9eb713e6a1aa0c2efa0158a59",
         Msg => "3a51f6fbfef38724347ab1a4f7aafb7a999aee9b890a19e87af6585dc16c568bff9a5148012b1da5e4d46c207d294c1bf8b6f18dbe4bb5f89d975d9b23f89ee84a92e0385b9f41be0c05ddb9eb2e4dee00146d56ae9b6214db24dca9515f996b63602b34d3f6fa57f3388cd80b6004dcfbdde95e21a329247dc65ef113474ffd",
         Mac => "589afd7086a58d77f046c59a419504a1");
      Test_HMAC_SHA256
        (Key => "1abf71698a7d52b41caa5c26558d46e8cf27a490d270168c23e4c0c4213efa7b0d844876aa438c61061c7a6e977f4d3f89b7b806572720eb99d308ae1d22cd8d38e293685e8c",
         Msg => "aa02f0b377f161ee60b0fbd6c56a537c0358cb8da62b63d5daaad203239cd6ac4ee8c892a8fb73256d6a264a83d8085c681bac706a9ae5de16f9dcfdf2f95f2d6f997c1b19824f4011a118abbd169001be4d7ec2226a85cddbeb4027708891f8f35e35d6334d9c46329ff880daea9573eb3768093863eaac13c6270906131114",
         Mac => "8cbd8f921c55d36e5b7db27f7891def1");
      Test_HMAC_SHA256
        (Key => "f8dff7f41b7e3ef6d558dcd83d344db5551d410eecb5a0bcc2cccb29ee3125c07dc8d2a25cddbe9b78b8e1542372c2caba073afe84ab7befde6250c595cba74f943c4cafbf14",
         Msg => "72d18951da90b1f6d908253e55da1b5b476d6a936cd6e4433efce72422f92fcde3c3ee795f0b1f0b8065174f6eaa5d83039abb1680c695af7eae7a712726f97ea5feb6b9dbe1bdd1537e157b78e699fe063503f5be754a505ebf2e9dd0a31086a2cb089ab6da32503b9a4848db5776d5368669b990abaa2fc6792a2f873a1eed",
         Mac => "1c649a21afe336c72c4593cb3d3c9462");
      Test_HMAC_SHA256
        (Key => "9fb4d6fcd697d4522dc7e386ab41dd9f8a637906e0fe123b7facabc719643172a84bffb50ccda872f6edf0e306d91bd130c26b0664eae4046eff52f71ba78de99d5cfc35307a",
         Msg => "eb6b60d0858d6f87f5b9ba7fc75acba8751784ef886061700047fde7f692d868800e5751d5260c7cb1b338b9fb168e7ba6853ad1d5a2229842526cf0e0cc40ecbff0cf8e30db94f22bb8d9c9edd87e09e506f6e3d11492f625ba02c2aca1195f71bad06ee0d48e51296ea697e5c921bafc42bf0dc6df38f07028c746a238e929",
         Mac => "9ca6f24c476e59b5b068c37b0383ff4b");
      Test_HMAC_SHA256
        (Key => "ce3a2bec5ca00b544e8d392ed309e9ee5d48d185eddd8b33902a3b9d291b711f721451633e27f133018b028b9149b3f32e39d20bc12d3468616c589e1b62479ef395be4326db",
         Msg => "36b5cf31af37c90334f2f4adf6a918a22eff5e3e54dc1a4f9212e8d47841fa05f1f8b093761c6930818e9a5245081d349c48cb1e41714ce73fae2eb8a91835128cdaf213229297f548fb0ad732ca38c05ed5ace1c67a601a5a3fd3c0adb65b9eefa4bd391b61fb5971826dc427b6134d5cee2a0d4dc1fdf1cb0efe75ede315ae",
         Mac => "48fc1d0123e5c7f686d74f5903323f9b");
      Test_HMAC_SHA256
        (Key => "b127e4819e172ca09868c28636dfa63b2eefd1ead22dd3f0db04bb3366aa37b53c52fc6956a46845a16a6698fe8c939e8d3e9f512b78f58339a69e2aa0a262fb11df313a92e7",
         Msg => "f1ab8fda839d00f0477d1ab6f3badd421834fa89a4ab8075ab77b738677a4cdf7d54af2a81d5ba9bbdb893cd2e8ed307d0f8e8111c19b846ce4b86ebeb111abf034e1cd3b3b4c29c6f7eab477e620a4c46c10646ca22610271de58d6091ccb340b009e7e21205f1ce53829cdec1ec83a03f81dd1b8acc4d01d98f5a0c884a865",
         Mac => "41fe6d923bfb13fcec839d3c272383a6");
      Test_HMAC_SHA256
        (Key => "a04b6205d7e712aff28a8d520a79547e41e42800001970b383f8dc9998a7482aa387e3ece6669044fff68c8cb27d5165e9cfbb4ff97a6a77274067cf6bca0a64749a1bedeb42",
         Msg => "6bfdc8539fe6bf99892c1c36d521f7b17c224ee3837755fee57a0dcecefb183e09e4cc1dbc19862253a2412eba0c67d2cf0ce61117668767af0d7c0a868c376fcaa48310a037cd6d1865c25060f4205638f5c5aba5a40d15ea915a34b4fdf408958714b3b3083b80c2bbc8252fa1ca459e23133997fa8e107c4cd2d4bf17f60f",
         Mac => "b6aa4e0beccfdd37588699435e2d40de");
      Test_HMAC_SHA256
        (Key => "beeba7959995358a1c238dc2f457f3c0aa6f47372f5f3471b85fabf1cba590589a74b385915501002ba5fc99094f684c45db476804a808f14a75fc42132609f69fc5a2090dc8",
         Msg => "b551096a194aee8992991325de92c9597c4d1c156c57b47036a7f93f2dd47be6f585906e43283fd8e4e75cb101d7f5e7a173eddb6f4ae7b7bef46502ca4a317240d7fd010189464223ac7ef6391969dbd5abc8c44bf335eeb72d4e92417215b79f2f974adcd5cc7058d2bf1b11c1eedc20ddf4f887bc65bd293afa161ab3ee5e",
         Mac => "98323e25ea0635d6abe384e8960f373c");
      Test_HMAC_SHA256
        (Key => "e7747f39b1c6c0157a9128c012391e5148200ed5006a193986040a6a22e48cbaed929b86e2e73915381462c4f0e74160aa4aa4d4bc0dae0485e5cbf8ffb4e93d940ae68833ec",
         Msg => "868bf010b6e26e4c1f91f0614ff42bc1403087c33b7e229af6c718880072024f5e7abce977c36c782daebf804deb7654298e22ce83652b43ad8917b6ef34094c29d28800b95b82989fdf91d8df637cf527eb014db2d8d2546c74ddd257ccd04c2dbeddbf4752bb95bd4eedd1cf04468d846fada6907e1eb67bb0f14200e15f35",
         Mac => "591d11b2bd18f982bccb6b3a44f760a3");
      Test_HMAC_SHA256
        (Key => "2f95c1d1d94db8ce7bdafc8af1b7e48fefd96b7ae8f733f72f29caed5db42df6f2248a123f9c4a9c836b4f7d54df7a9f405e71a5b5b29fd91ea57c654fce0ec723aab07f63ef",
         Msg => "852f420342b4bead2e714424eb0f287f077602047f40553d816d6e4e76588f8540e94d33c00d37ba9c63b8e83f393f8321b69c254858ae4a0fa23ba8260e1fbfda49a9b0969f4252aab44f834c7659bcdc4f6be96d9fbc7780698eae124d5641dab61d23cc54269de1cdd19e1aafbf52c3aa37f5f5fcc9ea5e2c310744fb7e34",
         Mac => "3d4a25554afa0abd26f72377c7180e19");
      Test_HMAC_SHA256
        (Key => "addfd600416f8511f3f07b03df2248b6bcec047003f49317546c26a4172f05d45f0c8d20136174f04fec550c08df6853ef3290af983d9c48dc86c6f87cd88000069571f9fd4c",
         Msg => "01c6d5c0272b631c3f9d1c0687f7c1496e77e1479bb9fc8f31e6e8b252297453e2624c7e8d1f1c3b0bc8f862a219fcb0edd52f1bddb9ad63fdaf06eafa45e1c5625de513ac26d98d794b095f196aec3751c7059b5b42077f2f863c17018427ea0b2069288c29e13d118f17a6f3d0db0321b4296e1f3a500c4fd253e170cc90e9",
         Mac => "2d2ac1291e545de46a42ce6c435518f8");
      Test_HMAC_SHA256
        (Key => "058f604e53051a0f8550de16b7245fdad3da639a6cc3c84eeabcc5dde8027390da488cc7f30772eb461673a32b7a4b4be47feaa2800878c200239756b9e0e807f964d037ed39",
         Msg => "a74100cf30cd26416e9878739dfdb3c1fa569d6427ca8ee9d06630e18f6f83db0df7248f6bafce5ce0fc21f5a34da2570bab04fef492a65866ff5c7a71ca72125b36ee9cfec716d96b53327dd35c9328a89dd498ffe3601d391e344de2b8e7f8d925e75fb1bc05a058c53475f6d38d1e1854979c0e66c62091ec41c3aae1e877",
         Mac => "08e3a1718c6d1cdef2c0c67660f7c1e8a45963e5ffed54a7");
      Test_HMAC_SHA256
        (Key => "986e0d3c3e7645e493d35962291d979ddf09e8a610d5a73d0ae7b397c2b1c35ec6d7fafa7294bc0f675abf4639b8655168814929922b179ae675a202dc4c305623f01865db53",
         Msg => "72c21be6f0c4df7cc8a53f9226f36146f9ec5bea9c94f3b7b604a8bf5f05f72484ddd7888c6986c43b6c87ddd727ec348a2ad1fc086929f17192bd47799e71e1c6a7c9c49af9adcbb16b699c6df0f8da3069829d09bd231f942ceeb81be0320c01c5fb83619bdcf9f24aecb72e750fa2b35177b3e9b86aa7e57945f88df3c10b",
         Mac => "b579eaf7706976152b1622c17fc47c5db3802aa3f46f6a3e");
      Test_HMAC_SHA256
        (Key => "7a41ca8776a3dde0f5c7d029f28a9bcd3c4daad2ccf9d604563f95501e256d6e0dbeafc304386185701d7c201fd258d8526464b013831a8bc8cf3292095316d5af4f97352d3b",
         Msg => "c7627c9a6d1e7c41c18657b598ac29b28c4d0ef047008af7feb329353b58624ee0dcc1b369594676718c085d77891d35e3adbe6844d5a7d2dccdbdd15e0cf39bf69e6ed58a61e8614074527740edbdf7bbca7afd2c2b80b6ddbe0f73ad7a93fc1290cb275a9e2aa936267e2b7840cfa11c8b8ad78569df4c0a6c6744b10b0a19",
         Mac => "53f3436a128fd497c5cd1a534558d6a6bdb5f086efabc6fc");
      Test_HMAC_SHA256
        (Key => "ee36e5784fcb43427be072aaa968ea52bf3b73f55d0b45fb1d996d4a1928725eae32399c805b26e3bea38465a8df27b54e6a4f209a18d041906b70d0d50a91bb6e6e1078cbdf",
         Msg => "8419330710968fb40ae915e66548f1ac445509e361f583abaf5f87173e7346295f4e3bfd0a1bb0447c2b85f424492d3ec047f9c1c4dd99fdfbb4e00a70bdc7898fc7b5dc8851fd92f49ca825bb0576e835921f3b8fcbde0171cb3054dd96da775bad290b53e07d86ba6409e2f025d492e95d03ba8c665b9f58cd025d4da785d8",
         Mac => "5a841e55fb2250c431fa397f1d0ec858b2c4a08e40dc897c");
      Test_HMAC_SHA256
        (Key => "27e1dca4978d2a05d3f9cabc29cb18c76a210b4eee825d37d915ecf59d1061a0c0740f4be0f81e92f442e872d45da35efc68418e8c8b949b9430b6498f6fa8a32dc9394e561a",
         Msg => "57d73f3bdcaadf51fd61aa65a01dc75638546dccdd899a1da25a086d23c05d1a5d93a157c34cf6168e0f832c54e9b2afdc569ba33106c0d6f5e0fa09f848b350099d56bc0c0604364d6f89ae14ce8e767aab0fe87adf104f4b9c8c05edadafd803ff45b2e061717ae488a2350956c371b95cb2e3e39df44f4d94a7a82c79b779",
         Mac => "dbeefbe2f550671d7fcd3d5bd66d19ce9faf5e6b29308ef8");
      Test_HMAC_SHA256
        (Key => "b415314e151701a503b62a5c8b5dba5ac357235a533fe2f634b85f04b85f1426cbfef29d7803005eaf3046684593e9543cb9972e451f258383e977bb92d6a1a9c8744b61ba90",
         Msg => "0c8404fe10870fdac0e8d21c99c73d04a78b6d4c8fd3cfb8d3ae87ee520e13880e7a2b683204ec4b547b36a1f7e1539d541fd9885af8d15af33c188b893e0627c9874e21a6cc25e9a11ea7404861764cfdffa4e7f9ded33d918f9a96b7c82b70c31433d174c902db313aeca1952fef392b929613766b1c88350fd5b6e493ca8c",
         Mac => "95beb7fcb2b8d049adef7e0f33a7792c8d71e10b71ad3efa");
      Test_HMAC_SHA256
        (Key => "e04e9731742a767445247fba9701ae17fc9acc451b8c4ff3af307c5fd3cece277c0d9b5d47aef5d9757acfd3337960b11f65cd1d095e025bf6dfe0d96bf19e08e89f696bb2a9",
         Msg => "fe1c33cadec693cfa53250d906d35d1e2db8df4300be8f2aa505600b44a063c60e91e7777ef4e44bde7a9a930e197517810234ad88d44a0ad30f84d734cbed08a7aaef69900bba794380ea7cc98363cce264807046866eef30cbd2661d4db2d9d14f92c79c73dd01db2d87bcc177f1e458c60db3c23dc283c52192e0878e7ae2",
         Mac => "2f8d11fe7f6c07bdd0d33dfcb3fc7dec51fe2048d1e8db44");
      Test_HMAC_SHA256
        (Key => "bc3732e901768fc9b98303d599110be8236c5151780022796d1b22c6e0f43fbe4debe3709c126e0f3dede3e17776e157fd64d67ec3ad6f960f4a53ffd33a105d3ac955f48112",
         Msg => "023004dff89f0820892be15fb91dc4c498936bfab92320eee6c117d412e3006c8fe3dd8382a411bc9378ba90e941419455d730facdaa435b1da9c1b4d9620cae966a772259ff59dc50ec609fc0ad276a3fd40afa23ab39903a1b0bf4bccc95ba7d8e7cc467f80708284e789328a89dcebe51a201a36e2915a7e09c9ea26bc219",
         Mac => "f51032cef423d7846270d8bb43f7d8426e392fd92b753a57");
      Test_HMAC_SHA256
        (Key => "d2229832e4000614fac6db5c0a235e49217fa4a9a831f9aae7f282eec79120dddce9963fa211ef0a07d21a782a5ed85d633ed8b8838d1f885d64aee185955f3e579c11193bd2",
         Msg => "0d612e1953e7cfde5242fae7d51c8152d2a4a7e44de128fb7a467ac4228653ae47aa6b1f0b608365ce96a6ef9747afbdb5950b15a619c0783777aed4ed3515fba4cd5854760001d0de6e04201d644826ddf563a9154ca64c2c4059c16129473a6af27e205b705008caf29de3311a557493eb38086322e061a1ca02f3460bf153",
         Mac => "a87d01c705415dea8cb9f0e2b6663b629f88a5ce793ea8a3");
      Test_HMAC_SHA256
        (Key => "043899af301424ed13d00066c0c37a448591f27371a284b314d2e7ec866a94c1ab502b67b47a13b8e9a86183a653fc27a4e0fe607a1a5d6064dfca224219d9fbe4f16372843f",
         Msg => "62908131c688711835177348434fdd1016941788765b50752430716e6dfe4f3dfe8b2588fa4241b14a35fdfa3562f1ed303567fbf74f0f63dc86f5555f2daf570095dbe951d3c9644fc47428f24fb7f603eabd9b2e60bacf58d1d85c33fa75830fb68b9bf3c56ffbeccdbf1aa59e95f538ba01b14415b782401904cb0eed0787",
         Mac => "97f3b4e61b5885dc4c7f69f79a07d7a40c2d1d2e3936b91b");
      Test_HMAC_SHA256
        (Key => "b5fee466f106d7a526d468468a16981251815a022073a402c4d7c5f6244af9fb747b3befacd85a3339674faff2f1ce174d661b6dd37d1fc8d19bbb5351f65c9848fad0ff11ec",
         Msg => "4745100cec0406cffa146350ee12213330d192123af4a1bafdbc5c98801eaf6ecb19724a0346a7b9d6b1fc381ae798ebb0501392afbfc6b8be48462dc2522bb7baec1605e665f2e42f1679b6c383fa1f00a35a01937b5aabe1f2174da6e0d7afdb680223de886fb9cdeee1b1320dd236e6716f492f4fe3fb2c61d8df73f03bbf",
         Mac => "1fc68ed1bad0898d691970b530b54cef7c2733a7f1ffd276");
      Test_HMAC_SHA256
        (Key => "fd013d615c6ca959030a520e148808a07e27d38a215634d53486ae8be43a856f3e5dc6eb4fd9874a8a6570276a9e7b25585af7e1ce39d325bd7d195f2c1bb95122118809c7fb",
         Msg => "fc0723c3f84de1178d14375c3307f0babdbb2086813f6970b8f477fe289ecd3900bcc4a60315d077e89406030155db741c002fbfa7568ada1709a5298ad12c39aabcc2b0d5c646847ca9546cc9f60f9485651e953869f5a49208560909ea17d4c4b025cbb887c9a611fc2a7fd3121484c191f7ef7ea23338f2999288ef121672",
         Mac => "10ab06d732cdf46a1711dfab98e136c4e6ed856ea0678efd");
      Test_HMAC_SHA256
        (Key => "05915a68f16938d7c6c5d4326904e0f3b89acf4d7063e01a4e38581575bf0e4910872dc9385436a218b7440e4fe294ea95bb446aa22f5b0c4cc90acaef83329411dc25fd462a",
         Msg => "5a40298e323ce97549d4c820b0a77cbdefeaf6ca9bad947a2b60985a0795d934e208b8334adc56497d2704ce7fb1fb6a69f94e3404791c1b962b0a86fc4cf037f960d375ce76146a0bade6caa4f705b5471da6dfed04a9eeb02e1623dc83c73d4852629ae7938ba09a6f575b48020367315fe6117fd4a4b91e70a57bcec3c50e",
         Mac => "aaf4fc8d00177a99d1c895d72b3a63e7ce15f1bc3946f338");
      Test_HMAC_SHA256
        (Key => "b05f0e3bbb12b9351c465ad5eff31e65e55956c5f4e4ca684d53509f8f199d1a3a035aab661c7b4eb5cecc678649cc4a6b29bf00de52ff492f1f93ddc1bd02f776d169146861",
         Msg => "99958aa459604657c7bf6e4cdfcc8785f0abf06ffe636b5b64ecd931bd8a456305592421fc28dbcccb8a82acea2be8e54161d7a78e0399a6067ebaca3f2510274dc9f92f2c8ae4265eec13d7d42e9f8612d7bc258f913ecb5a3a5c610339b49fb90e9037b02d684fc60da835657cb24eab352750c8b463b1a8494660d36c3ab2",
         Mac => "edfc7a2815d6779681590f3855e668f2c2d44e64c773e711");
      Test_HMAC_SHA256
        (Key => "3714707839daf79122c782416351385e88a81d31c9f641d8dce538e90e63c95892a2ea9b1962ed0ba372f48e9474aa730ae2359d6e4e66e449ee33b859576807e58999614d2c",
         Msg => "aac4256339f6377a4fe225d50e74424c80e0f96d85d162c410c3135a93ad397bb8e4e7bc523cad3d93706d2c7fc46a8aa0e8a232fc205e1744a207cd4e3f3b4bc54620ef20a6f8c2d052f6febeea50cdf49796549a3742f025ba90bfcbcb90633ab37902897b40916f516953b32e1e9ce3b57edb495d37d71bd25739f2995f4b",
         Mac => "ac38d22527983468cc48efbf64cbe1307022327207fb7f94");
      Test_HMAC_SHA256
        (Key => "c09e29071c405d5e820d345a46dbbf1e0f8202e92de3ed3e2d298e43aa4f846866e3b748990946d488c2c1ae5a6e99d32790d47d53d205481a497c936bf9ba29fa9c2821919f",
         Msg => "ea7240529980076d3b028a083ebc4e24efdaa06c9c84d76bf5b2d9fdb842e1038e487f5b30a5e010cddb4fcdb01ffc981eb0fcbc7d689207bc90ad36eef9b1ae38487a6dee929f3ff929f3357cb55253b7869a892b28f7e5fe386406a2776ed4b21d3b6e1c70cc6485947f27e9a5d8bd820380b9eced8e6b865206541be39fdc",
         Mac => "49ae1c4a7a570fde47f7517ab18898b1b991d03cfcf8c45bb3615b5f755da682");
      Test_HMAC_SHA256
        (Key => "bce50cdfff843885d4f364d69f93bf58a2322c707b82e878eec96d11e5db97bbb54606a3a3ccc3bba716261070a6f759a70ed3cb785fd1354fe56648df11863669b70c803b7a",
         Msg => "93b7ef0e470ddfac6aef93c0dcd37b8f1c4baf5eadd978e3bf0512fa0baeb099ff9ec1061b6172479b5674db5606ffa7e6b5173309370e1647054aafd5904816bad5e1523032cccd4d786505e241ac83a484911189666f287553d6a8164e8dcb0c85d75c4e29f624c97ceea64a2c8b0c9ddfa560f70fa3ff91183e4b968f88a1",
         Mac => "37f9f32918308210849dfebf8dd456804babd6845af07218f9d9be9df9743d55");
      Test_HMAC_SHA256
        (Key => "0cb35a02ddc8c7fb7c93aeab77b9318118b0fd449524209d879a1cd69d5439e192741f9c5c64a353a774e28681c58ced576783ba20bea51ed82ae50e30e6a147843130900dac",
         Msg => "21063443bf02ffe9f813dc6688920d036041a2a3a63a9956fc254a2c05ae03472537ef3489c93c7c68517c7588094c5e033434ab4b0ecf9e6c032c17911f73adcac6ccfd0ca57c427ae85127e2ad41d98bb94e5f2e6aad2e42ed26f87cb1bec6971c9446517c0966b6402321a06834997f3ab66756377a2f064d0277cf4e2bb9",
         Mac => "5c258ba6241f65c2ee5356bb47332236baea227857e29506165861a4c7379c51");
      Test_HMAC_SHA256
        (Key => "cddf76f985d6797c9fe3830c210567c5094fb979343fd5a1804c239a2ebe9a0e8ac283b0cdbe802c42e2cc5da800c4c1d89da72ba7489ab80e2aef0488dfa69ebc8434b95c11",
         Msg => "9724c0d5c989e5adafcd7527fee269ea14c0aec3ddb62596f3fdee9b0993e6c689466e877c0f6fb4aba29bc40343f53d3edb936fc04ba263bf00ac0fa7c816cbbde4ed09025ee2405a9d9229ed360b2ece058c20db7d8d28e43cff000fe2d5627a24c3c1231c463805e3e4c08462b5a50b65223bf4f1edcda8d872d6078a2c73",
         Mac => "3c5a9ac2a0fa2f58825233ff676bedf93d8845a409a42a05a9ae5218cea14680");
      Test_HMAC_SHA256
        (Key => "731bdc9fb219f3667c9a135ecf34c7f52cf638c39c554f1ef1691ae84e5a71ace915d9e91043a8ae6a7b6a6780b684f77b0417072f7e279d597cfdf02508c97bf4928c505be5",
         Msg => "12353bca6b0f3d545ec4b470c69272f72bb5589793e6ca769a226018c5acde83145567a1d6fbede5c150ec3142dc58f81246d4a00acf242a381fe51432447b7eaaf84c8d43222c0da3a0175aca442680a21cbca1d7f70097e82491db7f7d75a5fea552555a8de0122c3d9eb105d1c4d802c17963a1664706d3bacc345360b240",
         Mac => "f15a210fca2cefc4d92bf14ff572d021463bcc28f60d034e87222dc6076eaffe");
      Test_HMAC_SHA256
        (Key => "85806ff2a642f729d28ded0734aef4f6a3f0bb32771e77729b4391cae4b49bd0a15089fe74071e576099a44d22a0e0e3c5d1450f717f68628460b4eae3945f5893e39c5e8347",
         Msg => "df073817d8687293257d7ed1816803afe292d779f34e14b0c5ba6e0ac1e6c3b9e239f4f02110f4a430a71e906a3dcc7b0b7325bd9cf63600b25d4544d8556126cafb3e61e4894095d935d647a8560929ccc9559cb393b77472c707fbb7ab8838ff16be71091c7fee8aed4d0022fbe3428f5b0e1f216ebe946dc05d3746305f79",
         Mac => "6c63bed6c6082bfb085cf2426ef3d0dea97acd717a57ff0aa624d0b803f2ea14");
      Test_HMAC_SHA256
        (Key => "f13794e5ea5e27507a7bad638f8eb8b86ca5ad73b5a17424c63c74ef494bbfea084189c6fff5dfb2b6a5967cce3a81f9d9cde7a86f6b33927e15ee74e10beb20344bc121e754",
         Msg => "cd3f17355a1e254b9821276141a850f0b71cb3cf4824a803b01c71d8dfc31d31fd33ad1cac1776a98d18c6fd0598caa241a3af21772208d36f5270f4437570f963c8a323dbb41755d948f72369e7672b843eb0a849799d448ab7252e8abb496d05e44074715fd2f6849b02fbf6fdef3488d6fc8b45922fff0832d7af3efc7234",
         Mac => "d08563dad7c32c02b305b87fad504918fd566c433e98a1367a3dbbadb26e9b64");
      Test_HMAC_SHA256
        (Key => "e3d0c3abdef069e6e4fa35015797bd8a9d64bc9b75f20b028b12cca04a4fe80ff1bbbd88e9ef1003564d499fec88df4503671188eec5d7d089dd18b812c41db43a3746f77b97",
         Msg => "934dc1ef76993aa82061cf67aaac7714f12e25aa8f6f54840a2ae3d84af32481511d300126db7dc612a5b2ac0fdeb9c47eb316541846781e270c8ee5f6731c2e86c94e4482594c7e75d70ec43bfe7250b6778cb2c2fd3d176abf07ca5c051ffb9a17c4c0735bd059b2bd8db81553c94100412dce73dbcaf63a0af58f63f15571",
         Mac => "5717fc337916d66b4e292e69d507b1c81663d8140536670f3e70e33b04c83ac3");
      Test_HMAC_SHA256
        (Key => "51bbdf37124cee0cd5830e9d8f4b0ecfa44c8b1bb86a6433c18f6ee961ab694d74f93316e5833c44c5e83a039e5d1ed104f246e36e17f4c5445eff423982c883dba9707b68e6",
         Msg => "c84394086457d8fa900a57f18ea50a93be16f06fc28b5532de40541da5959bb6d2646ebe7491ef644ee39cb87d1219625b213094a4ed163dd707ef80dfbf9564f38195cdbb657babb4015071d58260c973fb418562fc10d95d67fec8a77f0bddf342121b82f906368b0d7b04df1c682ecd4c2b2b43dfcd6f370888df45fd8689",
         Mac => "3e0212e7982f43fc303d5e8457d2ab630aa257302ac489c74976cc5678823931");
      Test_HMAC_SHA256
        (Key => "e95751c99e14bed0dd9ba102f48e5e440519c53208e03ab7133613dad99042db7239347f5a47f9a8bbcda428ef52f5d7408235e4f3246268864c8c4135d27f1dc302a2d57695",
         Msg => "36bda8d33b3bc10f367caf71c5ed387fe5f1493c1d3bd2aaf97ad78cba3cc5704c0c02ed78dec72a5bae329f17639720c8f91817badf7511d99e257c68bca5aef6e0102a8e36f01f2f1553327be0227db32aafd8e31d8d575a1ca4145da7842e1d7ffa11e60be1f898fb3bb15b2b81a08fca370702bbc285663b7edc02c50cf7",
         Mac => "d965907e6d0f926a7ea719464b1034a5879c865a00d4df0342b2d4f4bde0976c");
      Test_HMAC_SHA256
        (Key => "9dd10a4c713776700f7e7e0a710a014b923bf228234daf5e807c8eb3e26cb97fd6c93d6cee2a5d7ab63c2c46e91c5b8be5044fe95d2a76e54ee5dc323412f92f7db6ceb03ee5",
         Msg => "3722eaa433830abdbcaa9177e373bab05fcb8fd82fc3afa581e34f08d3c07f5f58d0aeec9d7e71866c7a808ef15301251b470a9c455a612c16a586e8a5f1f3efe184a2e6313bd0a657d901319a9f44eb241db807a9474f3f49cbd2c8b8a225859ce5cd7b36e3af8545701a482780086a42f4a1ffa2b30144e3fd3b9052fc9e87",
         Mac => "9c22961d48d0651bd592fd369129e44822ee22d35c142dcb6b60a725bf177c85");
      Test_HMAC_SHA256
        (Key => "36bbb59925c6432139c7cd1bbc2b1b05c4010e09645f797e230131b2ad3468e7c9f2369b8b4f790dcb14dffcd6a941b262383341c80fd90d6d46fc8a81a25c47edba482c8658",
         Msg => "03074e714d5eefdf5b714381d80e694ef37c2647b374d8a38a6dac2a2e1d11dfa43c6de19d8b0e93061563fbdbb46c683cd86f58c284ed981399d4adb457f6731f21ba04168011db366bac3acfc66dc8f3281b7fcde159c5343cd9d98001cd719d3e9ea25e47e1ff13fc87055d4a53b741f592857c94067216dd23763a227e21",
         Mac => "a6109ba372c4564f4ed8c875619ff5bb64d503225197ee9259dd50264eb1f4ea");
      Test_HMAC_SHA256
        (Key => "ffa63ebba8239b6896bbec6af1c7b87b9c69257a0d146c0d5c4e8b8a99b43a18633f1f11b6c745ab05c5cbd8895dd96ad89cd87bb9fee30c373378ecf42274dcc02f3ef06ab9",
         Msg => "739f460034249e805aff665d6248a594250695835aa24cfa5d9c9b962f7d374abd0d163f65c51cdeb687f72b778d4854eba00389548a180fb6cd5390dd9580b6a1ecd4f8692d88b3eebbc77c42f2cab5105e425e252bf62e2fddade2c5424ed6a8a446d249422a268b029df9c96075de1baa19a8d56f2d8051357234ef6ae7d2",
         Mac => "c580c8e0f6a1f36403322f7b0ae3d06dd2dfd16ebc6dddd205704e97dc2998e2");
      Test_HMAC_SHA256
        (Key => "30be326c2ffff6d031affdab0a27d5a8cbfc4ba9dec626ad522615f77307e56d9e23f73e53c9f2c78cdeb5b84d2390727db5b3b4f4dae677d5fa7b161eec81b27d743bd56609",
         Msg => "082e7b4cde8914bf07c288441be643e408f6cb5ca932f67e9b975bd54ca706885468708009afaecd4d9ee846ab6c0d70a364c5a24131a766f558ad219e06e4f7e80c68e9d8289040a586662fca865ab459c037bf92465596b4281178133e7a806b214dcd747b24e0b681ea459fbd9276d31108fcc3f968d781106f20d3d62fed",
         Mac => "a51f5988a8f0f3992f549ea7f8c370a06d5ae8d65880067997536385d632b206");
      Test_HMAC_SHA256
        (Key => "19fb88775a517bfedeb2cde7c9455ca58d40d150b0a47ffbd0288e42e4725822c48d130eec98b13e7cbb044b846026f97f9f18531df9a9fe464a99c75bf9ff7ebf72e80796d6",
         Msg => "892525a0f02aae7f2264cb024632f11e8adbdbecb7d0c7080832e2373c94014cea02914c1542d1d000593fab43524fcd1f3a63670f6ff8509f1b1da881fb2abbde65ae27ea89a942bbf7fcb65b611d6e1ca20fb62b00929d68ae979e7595f6800d55637b98869f9cfc43eb6bb5e9c2ca281cc720340bfdb70bf5366340edce65",
         Mac => "974752b18d0dcbf29cc6104295e041259622cb7733cff63dbcf6808b15a5ad45");
      Test_HMAC_SHA256
        (Key => "815c2a911aaf0f8498706110a95e6f9c26c3ef52a3b13781448cb03fd2c887520df4a55144f8e206249b7517ce48afe52c11eab584f4bc0e4d5d706142edb6f0b67a99e82757b2d015d5",
         Msg => "8b7fdf792a90218f91998b084756f32ff81488466bcd66ceb4956702ab343ca59c15bdfd405f7e20ec61a36e0933f55fc49a357f062db0b6a7b613cddfdb812efdfee3eb5b617f02918ecde0e9f6852313d8fda41a64b2b5972124a7258ce8901402f84a62df4dbfe6e8b064cfe6cd044d9489bf8ebb9552ec9c4399658e9952",
         Mac => "7966440df79b13e95c41346eb792f3ec");
      Test_HMAC_SHA256
        (Key => "4809f31e93423cabf44cddcad23da7d7aee734d311fc7babc276a1bd3d35139861ead10369350d421d0af4944959cc006fee3f51b996f66031836a9134f1f7a0240a339e5e077d366c99",
         Msg => "6e4abd414dca21a6ad433146986273e2da952ef613cd1f9a0a836ca644f9de19d6c24abc77845002d9fd48333a447ac936518d1bdfc043380fd26316fdb5f6ec0f05b5dcef92c3d5e16498b854fc3db9b6ddbf098d4bdeb2c45305c2420b7fabc21be7eade7ce0e76c80071c0e13267a0540ab0846f758ced00d3bf13c84e11f",
         Mac => "d7baa0117d008af786c2bacb38b9d386");
      Test_HMAC_SHA256
        (Key => "1ce3f5bce2b176bf89eb7015005ed1ff5177a4746cf8ed7226efd49381e906e02e6359e95081af1683031c381d744b63b4a41d00e059941e4142f009c42c171e23783addabcdb640420a",
         Msg => "b6acbe5df01480614143c94790974c82d046352124f56a0246861042293152f7ddd65d22b491afdfa39092dfea21e318f70f18bb882f82671136ce9c5dcdd27277e8878bcb535146898d87354ada2fd2f694096de5c2d06944ecbca8bb2d4b444c8941807f81edfebce5af32f8eab716947c0f1f81d5dc70a94fe14f8a7644d5",
         Mac => "7588b290c3adf86198354e3eee4fc06f");
      Test_HMAC_SHA256
        (Key => "c8fcf6fcfbf498b33d3ecf12588a596d9fecc79ed43384fa4976138446ef9861ab0c9a8cd6c407cbc72878e2823ab706b5017f949bdd82032019b01846bfb758c7b0c6c3fcf397bffd4e",
         Msg => "dc058f909e7170bee56c4dfde862b4314f68314a9717ccbbb79bd42d0407db7552eb02c45c29771e66043b0e207a2997ced4346da67bf066790d542b96b0be33eca737f26e23f84dbc5b2e52ffdefb261428bd3eee7492d235d21c8f3379818df15eb6809d06fe322f98ad314d3632c46b8d542436abbce93311b4c3a30a2e6a",
         Mac => "99066156163139a8735711534c022937");
      Test_HMAC_SHA256
        (Key => "8985c5dbc6725a4e1ca26f5667d6da4938a8d542cab69a6938023075ee99846f5d73bbb8f49bc74d4b8f384aa1ea55ad88406c5ddf4a666b01439e973c91f41685a81d92692c3d734755",
         Msg => "48ca2fb5b7e4f471a20911af6a66158e45aef700ec0262ce941350dc208adaaf95a84e2cce2983a2716f690b21dce48ff580db4a29f48c4f148522ed5a958931633f81ab0c3af1759c007e72f92f5dd41c2f65e1c21569f664c7c4cc6a6135fa9cd8eebbd9dee7f20b05786b5a262764a004bf4c1d2da2ca6d215f01b6b68713",
         Mac => "0bfa572019e6d0f987f79b03ad67ad09");
      Test_HMAC_SHA256
        (Key => "e243c480ff1de35ff7bbb71963e145b20dc43b31afc1d4f4fe4ffc46e733b53419f3b99cc38c60869f67c5b72f8a2484470c87e5cbcba2caba61fbb26b534e79178c2f71980af1b570d8",
         Msg => "7e8bcb42e9c0015e96f4f802520a15cccf3fb280540e7108b251cfb97aa8fcd86d1eea5d340aa3f65234e14f5639d89155315729978e0fca914732b513374138c3c01f74cab36964cd740a1b1f59094d3554a6115ad2a6e5a3e2ebf3269a479367b692101383faaff1fc9bed1532500957f1c8c203a0dc62d2691ffb199ab7f1",
         Mac => "ec8356beca9d87dce7d010de113b9fd5");
      Test_HMAC_SHA256
        (Key => "2293336d9fd48570e6515a4d7c4985daf0e1230d6b6bd06589e71b8567ca3723fefff320af2cebf81e36005d4407071fc08fbe4f6e0804a43b7f491d389043e8ed71e283ef328721b542",
         Msg => "7d70d5d8676518e8f4ccfb3660bfc14e20aea6c775a616b342d21d3a1b421f819eebc9d106ef47f5fd1fb7e3b2bede9f2c881a5ddef398e67bb5c73c0b860d813f27b81501a337ff50d58a8e4b2af73f8ba9ffe2b63090f951007c61d67b2a34072d8ced810a50cd94f65b7e528b73f7e6163b9f28e265b56eba23efa4a9de61",
         Mac => "b7a1d83414cbbde7a7738c7e77cbfe3b");
      Test_HMAC_SHA256
        (Key => "d30c4a44e6429bb5a319252763da22b8593b7884c4ca9124698f677441edde996fca574374f08230a6b273f2dfd2f9f172a22bb3636a435bd70ab070c9e066e0ffec79453c32ea66b860",
         Msg => "20a0f85250a95615b7a40f25132af070aa388d86df777bfb03c0bf0d6ddf8787cd9718e6bde708b9998cad4e91c7d58afc60b719efeb2ac80f4a152ea3732792ee74c809bbb44fdf397b753809b409f796f2e6dfa5b223f82de08935689c4a532a3def047296934d3e794f2da47af57f1ff501212753cc5604880369e3e05894",
         Mac => "495f4ccb0530c7b1f03f3285faaae818");
      Test_HMAC_SHA256
        (Key => "cff586fb91a1e9d43c36a76a4dceb9e123df15670324d1c75fdb8c3b58310a8281fb1e33e6a6cd514d71b01fbbd99a363a557bd4da448477f6248cabb804b320df3c45ffc05be17e8b61",
         Msg => "e37e9da1ddfe11a2ff6a95025d1970fa1c2997bb7974d0010cc017ec4e36410c5a16dfbaf0a865afbf768ccfe4b8f446ae100ed6a477396fc9772b011e9c938e6925fc8335fef5481af36f163e1e66091ca1c476849b827ee35410e3c5bbf71b9813bda3b3e908969749077e74310e6aef46804122c6f255e4be8d3b4b7db4db",
         Mac => "836034775fc41e033c56ecf21d1874aa");
      Test_HMAC_SHA256
        (Key => "ece40441a168c83e0e356e687788081f07f4b299726c5f8fd89fd836ed84017157355e455700d78dacbbb8efb459fc0ed5bbcb011bc8410522c0716e37cdaae4badcf9cbc6aaee031522",
         Msg => "4b7ab71376d83edc4149b74ab10b7c1b1b6fa9ce977f2d63b2e321626306591e4174393bf287ca6ee7420d84467d90a628423edb05787bce6cbe71d2f89aa4237fd3cd6e8c1be59410f180ac54c65c47325f3af7857aec12deb4b0b379aabc026f5f1ab52cdeb6d72420b6c8c22f0986a18c432affcea8b66f8d860dcd7ec943",
         Mac => "43385c80a077720fbb417848e4fa0138");
      Test_HMAC_SHA256
        (Key => "a3a9c55995ea04d6ac3a93ee579f6e7c966ab5edaf1801472377f86ae00a1f97b8adf02e127c2dbcdff27334d04e127dc63b1c2d8bafbc95bf14c9fd15a69b30bf1c1e3c268a2473df86",
         Msg => "806e9111c731be67707d49b9e4248e82039608dfc6fa1645227eff6f30eb349b8c7cd6f6fbf0785550de26259049a6a55474fd536ff736a3d1135ef7ab43d3ccd413bf316c35df7ebfd289426b1eed7dc62f9b107a0f45717210c6a3fa5f646621dc52ab6229794a840179f7bfccea732070e7ff2f69cd16ce1c405b64686fd1",
         Mac => "9014a5bb17057eb39ab9fe59436e6c9f");
      Test_HMAC_SHA256
        (Key => "ccf7c4e2a8e7a27c7bc54422214c880e7c2582d0680b1395f02dbda8c2d3b539e0453a5e99e92657b8abc316fba1dfffc6ef23ec19e9a074c078ab6dc9bfebaf3bfeb01b05b686dc350e",
         Msg => "85a438185205f773b7b39db2a71ee86aee341f9b2285a2edd7a5c53913d2de4b02d79de7ea309c09606f3771bddf9e5fcc66289cc5b0ebb97f89899be18b4c389afa769b11ecd22e9fad8f38fd614ea5f8eb7a066c0ed8d86fd25f09cd2a49b8b5d36a3db17fc169db334d0e4fee21c2dc8bbbe1ffe892d11148ee8abff6fc55",
         Mac => "e4c09bb7f5ee13351baf8f4fe7386711");
      Test_HMAC_SHA256
        (Key => "8a81d2ad65585e1e1383783faa17f460c39560ab730f95657d8c8c71c5ae731608920002cbf8068e91a446435104879d2712e9104a7c76493e02fab64b2014482dee8e780d44ea88b021",
         Msg => "18915f3811cc77d3d9e41d543f3bbdc827f5781cddff193da94f4b7da46d0a39c93258b84fcf31573712c0e321e5d34763188d675c605a4b069f2880cb65d5bb9ab7e3c039107382dda6718cf8ee0c9f5262699d5b8298a5c019c7803cc1b53cb1a96a167796269ef32897156c5f4e1a1b5d7486816eb994fe458e459e899402",
         Mac => "a43a35e87ddb24ac3420c60c99090ba8");
      Test_HMAC_SHA256
        (Key => "8281addf9835f1308be680dfae2dde6c52a58b698c9ee3d3391643a240e56d9f17372e76893f3e0cb62a67125b52e9db53b51e6a5ea55ad022c115b56f234c34c7db24ec1e9cd153deb6",
         Msg => "48dd9054dc7703793557e492fc0fd0d45db0de0ec48683f1e402b3affef849c9600ba9212c65a4575aab9c52002fe81dd16879f5e4a0bea0b8edc6007462a5e77386182dff056c005da69b7c0b7db97b45628eafcda285eeecf4c5ccb4ae9d6f8938259fe0c1221d45322b36a3600a97c086656307f29e838afef73e4742fa09",
         Mac => "d02c59ac11fc434a37eded33245701bb");
      Test_HMAC_SHA256
        (Key => "183b4cda5c0282dab62aa4e48a19d3a5a00aab5524046e45f1085eb70f8f6af379340d9724ad742f3effdf05b3f2493bf6c34b16fe1a3e9d8f3ba063ba80b8a1a7077d8792a8b5d4142a",
         Msg => "3978b24f0bd0829e22c0596627d9d6d858f1c69b8c19486771cf30d01975aa5fb50220e7a0f85d169f96f24b674ed8a75f795867a84a28715b00d72c11606a95a9634890452c537b963c58095ae9a94e220c081659fbc77b82b72eb7c1661d369d03f2f00454adf58f1c5349089390f32a139f51a7146fae705afe16306d0969",
         Mac => "c6d5ed018b85568d03fce635a1332e1b");
      Test_HMAC_SHA256
        (Key => "fee603258582e3a3e8feb886599d4ac405a1634c320e85ea8ab0dc6bb65f72012f82a2e951d2cf4ab2615661b1dac0db520a3d82499f4e1c5430c190ce7ee24b82faf0e2bd87cef9a780",
         Msg => "67541f77f4e40d143035462505de14a02124b992ec1d0064bd15185d4d30a2696c510919f23b12eaf9f6b4ca497529d81475456ce4a80757d1136e6cf7b48d3f2769e22cdd0de49b72e4db839339f42df245953b3b53eee84a22d1919b8bc375026353b99ca3aaaf05c66457cb739e26235c5007db66dea0900ae9d621fb6b93",
         Mac => "f914c842b78c3b91fe6626272c04f6bfa39c586d4823ce0e");
      Test_HMAC_SHA256
        (Key => "832f87d596449aeca656e0e0b4ae92dcd16a66889020a9d2bbc48eee45ccc69b809150a990f993b82053aa425382ffdcfd5e1bb81457bc6f615c28fd7bfbc20df6c9db78d804ca084c77",
         Msg => "782ac16bcd744ec016ffb6b014e0c8983dfde231fa72c31212349a7766f46240e047723da60350a893ecc7f3e79039c53d6f363fbe5f4c83952f2177a28bc0c6731f312870004ce45547ce93e6ffad26de41a92a289d244b51bc33173e44f5051afc24b69331e97a4658f51677f4cdc506ba657c9ef3f1723023f8e0a0e8aa05",
         Mac => "c68f215b059881c9f97117b3c6d9d6deea2e0945e3e1972d");
      Test_HMAC_SHA256
        (Key => "92a0e01315efb0b347666581560b44bc582ab63e8f8ea651ecf72bc3d3c9673d1e02afd0646eebd17b1e40e73b16ed62854673ce84bcf9c83317ee11203ff0e16f53ed7e21e3880c9760",
         Msg => "7b2f5c2741338d25d8f9d4bb0fa718499ba960c65eeb399fe94b59c23f4e81f5db11a86df583559c02d24d4a7a236ee7dd86db20f82959b065ccf9795174f8d38164e3249749feb192b5e7b395ce77aee948e9fe44903eb24c4adf9e57fe85ac750e5673b0ec510b9289eb1fe811fa43c6d5d388cb89af4ea6af545ad953f129",
         Mac => "3d516a213a6b8c7e3434138238ca5e339fc21038fb7bfd21");
      Test_HMAC_SHA256
        (Key => "ce4c926c0922ba36269a20d60dcf08d43a1cea120f266af76f1c8acd883d1f68f09b8209f41f87822dceb39a544aa9b2569ce6a9ab30aefee421463484b8647b112fe48c6bbabcd55cc8",
         Msg => "8917aa6e1cd35af30eb5c7ac200e54835d4a0777a06a2fa756b44aac85a8252c0e3745ac2f3086a64bfb02dcee8934eb0c8b5e2389e22796fe57896fbb8dea8608338931b17e1c5cc1d7b8dc8dd1f000f45d4169e641ae1c23c6a7d645b12fa001753ea2aaa7643cf6b2b05305ccd0e99f2979f1be6e0a614c686c882dfe3ca2",
         Mac => "94c47b509bd0c9b7aa95289a00a8a54efd425481307e9ebc");
      Test_HMAC_SHA256
        (Key => "0649b582dbc59816a8042cac30cee6772a0ed8cbe8e07bd538ecab8a88f3f3dd4da70b35a5c09f1e3a4c523e6a46038ca66b4fbc184957fd8999c3e781ce07afb0eee49e8ca132c13c88",
         Msg => "1c685e17890ee079ee85cef5ed709356f4199e657aaac0bc85a1d5d5707ea666ebbe0ef1430d5c96e4b8f92d1c614b9121f6d83e56e4af1fca8704a101e51a0cf89d6613631af1aa390cfe177219ed4c10cf5f745cde9bcc728430b4ff48dc064aebada6719c665af56b24dc7900412ec78d792e14014b6a857fa235f20eb5fb",
         Mac => "9bd70f0386405c04d1bfcaa538b4099abea343c5c4379482");
      Test_HMAC_SHA256
        (Key => "3d7094e005eaf0b1231cf60536f768e62f79dae86374660bde91a2e2fa94cff531e2536530406ace2cdd187179936293596abd20125ec7944362351b77a40cf7fb131523ed1f8a3696bf",
         Msg => "9706d7370b66bfa78abb8b25a9d6143a9aadcaa4f60c9baab98717ac8fb3d2fe4e960af7c35b8a44b14ace8217f8680db2bba312c36165ec12225aad33d24efa085cdb1d876b4555bd6aa27013af3e9cd1f33d7be0068275d4c0d0522a3b2f08cd3f92d1dffeb681b7024d1726635c92ff3de206d661baee074bc2c4fb553dcf",
         Mac => "59526ab645c2c0f464a48e411d111abe9aea19edced55383");
      Test_HMAC_SHA256
        (Key => "74d72be7fc8f4fd566f863ef53bdb361137cb6d96b79efdd95941161897866997b16710ca552d3ea46fb6b9feb01c1a8ede2a5a53b6613b0598c5aeea9c47d63ea5eda0bfe430926f0e3",
         Msg => "ff8468cf11d6190cae4a1e16871ae0817214fd441a889bbdf564fdf5779e542686d2d77a2d2d151694898a5730d9715b37c8dac4579dfcb8a762cc2cde45cf63c33e2cb1e4f205858bd807a7ee9a40bda6be31146285259ddd13c1360dd1db2b9e1090fd9eef90627a7ebd8c2923f5aea73d2bbda508bd747fc1019a6e0a2187",
         Mac => "8ce0b5dde0328c9de6d4acf84ff61b3f7d01f9e9e8e36b91");
      Test_HMAC_SHA256
        (Key => "94869ff7b6164a24e89ab734f20322421bd31581548139c6b41f6d46243a15a05c02b41e0eaabe376012a759a0a440e6337c437dcfcb2c7aeb7d4bc0731918b6bfe9c68fc65c1bcf8fa8",
         Msg => "32e5a9f3c3f9576a21dbfed017b961f118cd23f3808f2c2b1d294e35ee2b28432a804bb584a19ceaae08fa561ce820d50a1bcc3fc05b213d15b6495b323c605e98fb8dd7652d72f8d2afc7a701b541d1f6bdb901e3c18a31a8b13be09a205e64833eb782eb06a13c96b8aeea4e8a8e8ce39a325f6f2830aede026aebae3febfe",
         Mac => "549afd1666a491b7ee9ccf6db2a33b2e3c2a21cfa69a1b17");
      Test_HMAC_SHA256
        (Key => "fbca586edfa57645037b6b3cd70fc341e4d4ec97af4b3dcbe18b36e9a6210aef531b5a824b6044e023439c16045779735184f43c8a5a2ca171a68ef06b4353092833491286eed76cb3fa",
         Msg => "4bf841ec0a4211b05f9a45a127bbbbf6434e8642910e8ab11b2a468e8feaf009f096c7388a94a55b2bd0d364906122b71e69372ed33c27607bc544232726364fdb9f4dc587b115b038832b0b908450647452bcdf04dbb47dd0c25f9e4804d6c575db7a9ce7e28a38ef7af59d0e6d6c85acd2bc5d0d315b9182e74009dccbf8f4",
         Mac => "0cbfe6e817d297b69d5bd7740bb0e5172d86cf870a9c4da4");
      Test_HMAC_SHA256
        (Key => "624248769dc2742a13e6b69b5e7212ca459b36bf86be5dd8d35273601a1c7a6309a12cc1d2e1e2822b42b46999cbe2ccef9273a311781bdefe1362fc0eec03d978eb92c7160f62e16d62",
         Msg => "633974ba735a5e57d1e804bcdd4d72d4a9e9df0fb9bf8db2076ef1714a64143f784e39658ad2c0d17f814ab1a3071e4111a5cce177e2106b197df8c319a549b0f56c20ea517ad574f7fe242b1ceb8fa0e560fe232967a92079e337af5dc42766e17d707150b864e54048da52ce5f8c982b01befb58b821792d8af65aa028760a",
         Mac => "ed1fb08b8473af53d2fe4c607e5ab9639cdd11f728462294");
      Test_HMAC_SHA256
        (Key => "25cdcc9cb014784dbbdbb13f56ffaa63fa234c916f02367dec0303e8810fcb13b29fec7965190abdfe5c54e2c89909ba97663ba1ab0dd46bd82ad69ae475e7d431dc0c959bd5b522a4f2",
         Msg => "ea526480a096a4d89306b3cf86eff742ab46e4e9ad991ee7f344dd9f24e896cae619d8c6ec5774312f40e0b77b03dd282e1858ce3d2f8efd776674eb0ebe56c253d0bef4c1bc97cf3d6392519cd6c93d660da36ed9ddf76c3124743d2747407eb8dedfb227ad57d945d79145f04e03a9da8e8c738c8b9f5baae7a43c78699b23",
         Mac => "4cb070e34b3a2ecb460670ffdd457f23c9a1174bccd35f25");
      Test_HMAC_SHA256
        (Key => "3ac105a2bd07056d3e1c3ba547359dba94e8f79a6c32ddd532bee4ff37641257d2f192a5b326ac697403f5317145c34bda2de49c068390d00adb9bb48b17efdfd02d3a981b2ae4f43a77",
         Msg => "f6eac4c4099c3232df018fb3c837527b8021a1a20cbb5d1be5aa5ee5581800852dbedeb38742dd540bc46da844b40bc546e60a4492e8943a3a93ec6a46e0f5b855fdf8e188a0a26a9b9c4cd655b2801c23a9b85800a068c197a43fdbac7eaaeeb8ce9bb6d35e885cd7b0b6a5c3d9b76a5d9232481c8de2984405e1a15399270d",
         Mac => "e5d5cd2e163ec1c883388f5f01980d3bbee914586ddd5b0e");
      Test_HMAC_SHA256
        (Key => "b8d9d674cb623d7a449411fef509558992b7f6e314c64f855c9ff2511946a681ebe9acdec9b94732a0f87bff3c5314716c73ea9261cf64bd58c43b5579e780b6fe9ae16c97dd28a40d67",
         Msg => "c9f902c8c02c5b24bb54e2dbf5c9573bd46bef39ccf15462817eee152b7561f03f8f57884c2b7f5d22e5d60d3a6925c7528aca03588ebc7089ccca2eda7a233e97c01b374a102c3adeba3b2704bb1d11d6d65af0bae731968a73dce5f283153e19b3d83c83866ba336fc9c931b674a02a87a2669bca3bbbcca9baca03a3b3dd9",
         Mac => "64ae3ccfaa118acc556ac50e53cd9fdf7d7e3f4b785b2e20");
      Test_HMAC_SHA256
        (Key => "c39ce5407c0c03ddfebe82dcca408c52f26b64027e38edd00dd57079c0f89a825374c46e8d0a7834db8130f038f860d94f7cb773e4d6a20670a6134e0bb680748f882e3dfb31af82156a",
         Msg => "c1490ae9579828b2d6d2935f417e0dbdfff5d424de5ec50557ddc7c3140867c4af9bc0c7bd6c9e780ba1e341272029642247a84795de5a0ee2495e6fbc029bc2ea47a5584710e40e0e44f322542c4645d62810f1f5a163fcff3e996eb05bf490f9b78145ff6c429d67258ba8d18bad88a200d2ca079028f737244265f8f9bb53",
         Mac => "0d2e37440adeb6836d7f47d9c516124ebbd64abd435d4c98");
      Test_HMAC_SHA256
        (Key => "318608b213046a3badd1655c51135c7e1492c6cebc0f2f36e0d77f8b4a987f08a07299fb4451e0be787b50e9c66556c69fcb930542ffddb1df828663fcd1e1b6198103fa8f8ec72dbef1",
         Msg => "45fcbdb93acd8300ddb88012ceb55950f4da61145adb0d4c3dcda868632f4777ae2a008cf01857670144f9510ff0ad48369d875c50865e590f6e81a6499ba66d922323fc1066616c8bdc8d80c41190cf08ed42260439da28db5faa37767109981c6d90d142c08956a408a465941eec2f9254fa381efb6800ca2989e393b9573e",
         Mac => "95b0a9f0ed9fc80581407664300488f5223720148618b1b9");
      Test_HMAC_SHA256
        (Key => "81574323c973540719d192833ddb51f13a52dcbae294aebea51be5f6aa47f3571f5d97facdcf0c7befbe809f44bdc73963d8514e4fd559774bb96087ef8eda6e7c64275d6d96c42b4e4e",
         Msg => "b9e944e0b42d0ff454f7f8aa24f00e9ee039058ce4094111e39731b6dc3ade2a4acec4cf9c5be078e4f10a72d3d685c1e5e4d5abd92cd07b64dff87f266f0853ddf1cd61d9c637a9b07ab0be32ecac119faf827218b17ad4541a27519477f76ed918089f54b63d0e1e5a92982979ac187764b5e989e066a61b1065340e9cd203",
         Mac => "514bd18495f6de0e237054b8e3ba1a74c3fada4279ad6b8550f3a14712c528df");
      Test_HMAC_SHA256
        (Key => "44f71c2317cde52151c84260d1d3c04a28cc15ce5b3802b2e5357e2bfcaf10ab15d77dfaaad1a3883bada502939948234c559dcd95e7e158338fa12ac6fd21874ec2ffabed051416ef77",
         Msg => "2ac0bb0524c22b902de34ce64e6172d1b2074e159f517ab1abd152622cd10669f03aed8e2eb51c65bd0f38d084e288c532724e512fd558ddd257d2b1d41c5eb6040767803ddbb18b95a035c5d8492d4d35936b7b3630ee20f625b70f8e71d9dcd0efd0e3387d138c1f5eedce32dd88f223334b9a9eab65017f04aa8442179f62",
         Mac => "ca0053d51f6cf6f9998ff1e0db00b90e82c7b18cb5377acc8ebe9afe20da1c3d");
      Test_HMAC_SHA256
        (Key => "7edeeb6b63c3b9c836c4843ba46bfebd8ca9a6e205c7ed68a29f9710f50c65ac519ff17ad494d9b0a5041f587b5cd05e5f0de4e8b28566e5715fd5e9b8d6c9388580d921bf39bd8d775c",
         Msg => "f5aff283b3aaa4c71b13c590771d8bd3358d76988ecd1eae653c2f9d72c9b2dc9fc08e44b2e34ec52dbd245872332e342b5cf945e99344da0bca069ee221b2c913b7b9973cbf50fadad7758b6a962cc7ce640f78f38f0571b19b527ef2d9d09b173b7b64976633cde909be13a56d0df3e64ec019f2eaecdb1d571b27ea1994ba",
         Mac => "5131ce486de164491b4bbc84e7e461a874a2cfdd769355584a063e306960acac");
      Test_HMAC_SHA256
        (Key => "6e1b663e808a6986f29956b7b9708066696f9dfe0d7bcdb55696d8bef9b3b7c052c857884d2499fb86039d4eaf604079330ae3e818fa6f742ae49593560c5bcb545bd46d89b22e7f2b7e",
         Msg => "c0bb12a5da628363a71f1f5c9ce715ce8995e607148d772b669f6532242f9830a1931bd952bd2a44821a8def46b92504b4b0c5da50bc43bfc727cef5e0ef81faaf24390c0c92a4ed43a09be40d78b204bf680db0c288755f439eaa9d2b3efb5352361547ef2919e65479f142d86ae35714856692523b359442cba333ef662ec1",
         Mac => "665344e5618e0c1fb8758d049409a484fa69b89b009746067ea036bfa0ee8a37");
      Test_HMAC_SHA256
        (Key => "208f91ccc87965d365cc325d3262b64277f6112b0b9371a4174cee721c2eb32638735ff2a5f8abbc82f24c71d6dc1b9cd2b473375666dac0b789e490c0495569f6a4864e20da0a97071e",
         Msg => "854b32866273c6eb110e380b8f3bfd169cc87a6f6149c75e5667b305637b0895465c10c134745773c31ab3be071c8215fb9a33ba231b087870da199564619d03765965d6b8a1a9fbb79d0726a3d1c90cb0ae67d3bbab4cc63198dd4e2d2fb81de0ed39ad362043e9b6403d2aab825a6481ab1ea271221eaf614a0716050ee14d",
         Mac => "42680195f431e71b592899686af630e15996dc718cc29030163d677688a33021");
      Test_HMAC_SHA256
        (Key => "915794a6c6540f1ce9958c2784cefcc13772198cabd4fa17c88de45c281d648dcbd59a100cf4d8c8d3106c960db7b91f59578dd0045bae203897b61570e6210a2f11a5aff2f3c25163db",
         Msg => "99494422460ec858a24394f603b1d9b940a24ad9c6a3d1e9e88781fe77afcd139389f7acc057cbba3d328cbf914e2f32667fc7259afc412594645162d4feac10ce45780cf9a400c3237ead50077132e421dc066bc19e176c5f21bd312e98ec29f384af8a187dd13afc2fddf08ea34a971ac0eff36311bd86f1c8acb5ac03f627",
         Mac => "2ca1bb808448eb29085286594de21e254fb3416f9ab01e99ea33ca83c1d14dc3");
      Test_HMAC_SHA256
        (Key => "b1a95aa80bac5acb7a18332fc03067600610f376d99e77a272be96063ac5a0ca8d316e6cbe978e575cdca1b8b4a8008d9718a6fe5eb34af12aa0cbd97116d1ceb613b2e3975192b40d76",
         Msg => "d8efcb416f237c7e05bed9212c543011c39e6a5f25d7e2cba065788a29bce1464d8041676be9fb91216cc76d049806ad943e534a6fd45b10c41bee5d0b005626f3c0e73a9c50d7cb07fc502acb4ec4d2093181a8a1568581a6d793e5101b8613b1f9e6446b20b9349fb69bdfe83f11880ac11b00252508252fe18ea9a0d41a15",
         Mac => "988d4a6fa87f8138d754c5de9d176c45eaccf8eb8ca1799d87c8f04a966b6f4c");
      Test_HMAC_SHA256
        (Key => "9e4ba7d72b76edee6a6f290ed318bedb0ad88c8411f9c449bd4ffb3a661b7e41e32ee662b552ec4283e57ee6c7c712bec6773ae2c578789b7afa5425c1b6adb3901a4db42da6c0559e96",
         Msg => "1a0223261ab437a4ac1701b4780776c43f0f8949b3e7a1618c3b4ab6d8ae2aa6921f38a2772b28d415f32905251fd3bd1a235bacfac00a486dceedb8143acdf11b4b611f1229c346f89f21299920b56b1b08f7f4d32511965d7693f0eb326893dd0c096492b6f0427ea450e87d1203146748c3e9e51d9e9183baa42806a0e3d5",
         Mac => "ee6492a669e22bcf19bbdfc45495cd0efa9c2f2ef5d42831e3f13a545cbcd6a1");
      Test_HMAC_SHA256
        (Key => "8fa12bc017bfeb6c894020e420c5f76f9080e8733b998ef3a7d0b6563063b66afa3200a82a21f6ba56be003a3924dcbdac1f3610d29079c19213e4e14ae0e009c1ef919b5e60ab4a9819",
         Msg => "faa6ce40d931f3c0cb4538a82a22f0d4f3221f027b99d3d85dffb729b751e57496b4fcadae5c72404fac2c54949e4c4cde664b948052479abcf59e1aef84bb9f088030473e9505c603c350ad33bb06ed928c1196757ea3e5bf3ec97e0f3c43f638529394f2a65459cfd1cd3d7041c6bcf8db9a91c1e58ec24e2461dc81412580",
         Mac => "9611e838fb1d816a0ff9cd269217d93258c34df9e26b74476fe4da0f7dee2335");
      Test_HMAC_SHA256
        (Key => "c18bc28d496beedb25ca42d1b217bc81891d4c2bbb35380e5bb9bf7e3dbbfd37fef70ef14407763447d6c06e915766430277f124165061236b9fcf057d785199b4381e49a2bcf3ef85d0",
         Msg => "28b18b862ce9541ed6daf81199f9a331133b0ea3e48ff486c1acc6d5c40e9f8f063b7a15704ba3d3cea76b222511206d47e53c93a49edd8d639b7551b224c3f65aa802189648607e259ab1fa9ea665910435b7dc9a4c28aef8f32cf85f3a23e94a7e8a5945e9736702383261aac15ae571b4e8466da1bd31a83a5291745ba7af",
         Mac => "0bb4127d89d9073ea425c303adc3f9db39e40adac23ea61fba8b6e251d79390f");
      Test_HMAC_SHA256
        (Key => "dfd4faa6b9ebfff6eb33d4b536f3f18785fc33e82ddf3908735d0fd94f1f09666fa8f2667f876611a8d17d3256ceaa7e3ff3e224a11000a5cacb68e6de4dea84d53bea67c3e8be9a5cc9",
         Msg => "80f20152d12b0a5993a2b17d1f55cfc0c078961ed00cd1c21db36d7a92c339691399eafca830621fdef232b06acd5d33108a5fc8c35a6d5b0eb2ff1bb2598c2d91c094a1ca91e4a5268a16f8b38c57a2aeef6de3a619f869df4ff7c5f5ca8f20c10e082a807719543215653f41ba45746350c855c170f85459315f62a13ecaaa",
         Mac => "109ebb4cb2ad746762b6652fc63b99019857ae89acfe9807648c3cfa151fed42");
      Test_HMAC_SHA256
        (Key => "c96c04a3bb0816fc47e05913a715fbac9a3ad09db75b48e8013d9f27bbe8532d7e63dbea88bf968f575602f377552e35987872a4e3155ddb8e5cef30aedd08504d4b2123bd7f3af62bbf",
         Msg => "b11389c7dc20ffd0c4a5f887f2576bdc302c7d2af7089a012799c528fa7f2ce23bb10071b31c83d9e58d63e6fbd04670ff1aa6de4ea4dfe94a9986a35032fdb7ea1f44f2452a1202e517257e97ced627a7bcf06e5476c236819f73daad0d96722527fe527891d4d42c0ce658af97428890da04e1efc56c6f337534d7fb57209b",
         Mac => "b53db6bf0c8317586ae6c1a1e2857f241bf55dddd1b423578c6949d4bf014611");
      Test_HMAC_SHA256
        (Key => "9319838432ca096960e2196a06398134ea06e4e8799ba470c54f0512cabb9045f529b6c4e749b6e27626c11df4595bf5b47c04ffcbe218351485f49077405ad96a3f17bcb7b3e21e80ca",
         Msg => "57e1d3ff5fc4785f9370df2e5abf454579752ea934d2a9bab568d5aeb22ba43e4bc7df9f31366bb40d91ca822026e4e426cc088081732ef993ff7f676c571704a5b809278b50a3778108f4589fa18caa9f0283b3fad0bd594e406b950329d5242e5e5880b53aaa0eb57c66992055c4ffabc0a72ae712de42add2a321c0ca6808",
         Mac => "4a34bd4dfeef7fa1dc739280f16a3fe1281a51311c10a920ab43d406d4ae3370");
      Test_HMAC_SHA256
        (Key => "2914da23e86a603cda1eede153be2431c2947cdaeed6a1ea801d18e2c218220ca682e40f0a51c4c13a31163cb730f83437bb7a88ecc903160956f0d483137d1d145ce948866ad57f2eca",
         Msg => "6b8db9acdfd24150808a92368596557181d445e5a04e91112db2812b58035d72378d8bc00a1ef75ec373b81dc6f1f0a2ed96f302cf2eac8f42ca3df11e6ee678440a28b0dfab2a36eaf35bcbf3c759a71e47120f6c03292a3d6b9b111488a2259bead9a5e7e2a180fcf1c467947f59271cd0e8360035ce8b287fe2b3c3b95822",
         Mac => "4de7bab7fe9a0a9bf7b51a7cdf7d929f2b1c6ff4575fd527baba1efdf4254890");
      Test_HMAC_SHA256
        (Key => "4b7ab133efe99e02fc89a28409ee187d579e774f4cba6fc223e13504e3511bef8d4f638b9aca55d4a43b8fbd64cf9d74dcc8c9e8d52034898c70264ea911a3fd70813fa73b083371289b",
         Msg => "138efc832c64513d11b9873c6fd4d8a65dbf367092a826ddd587d141b401580b798c69025ad510cff05fcfbceb6cf0bb03201aaa32e423d5200925bddfadd418d8e30e18050eb4f0618eb9959d9f78c1157d4b3e02cd5961f138afd57459939917d9144c95d8e6a94c8f6d4eef3418c17b1ef0b46c2a7188305d9811dccb3d99",
         Mac => "4f1ee7cb36c58803a8721d4ac8c4cf8cae5d8832392eed2a96dc59694252801b");
	end Test_HMAC_SHA256_NIST;

   ---------------------------------------------------------------------------
   -- RFC 4868 PRF Test vectors
   ---------------------------------------------------------------------------

   procedure Test_HMAC_SHA384_Prf (T : in out Test_Cases.Test_Case'Class)
   is
   begin
      --  PRF-1
      Test_HMAC_SHA384 ("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                        "Hi There",
                        "afd03944d84895626b0825f4ab46907f 15f9dadbe4101ec682aa034c7cebc59c faea9ea9076ede7f4af152e8b2fa9cb6",
                        Textmsg => True);
      --  PRF-2
      Test_HMAC_SHA384 ("Jefe",
                        "what do ya want for nothing?",
                        "af45d2e376484031617f78d2b58a6b1b 9c7ef464f5a01b47e42ec3736322445e 8e2240ca5e69e2c78b3239ecfab21649",
                        Textkey => True, Textmsg => True);
      --  PRF-3
      Test_HMAC_SHA384 ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaa",
                        "dddddddddddddddddddddddddddddddd dddddddddddddddddddddddddddddddd" &
                        "dddddddddddddddddddddddddddddddd dddd",
                        "88062608d3e6ad8a0aa2ace014c8a86f 0aa635d947ac9febe83ef4e55966144b 2a5ab39dc13814b94e3ab6e101a34f27");
      --  PRF-4
      Test_HMAC_SHA384 ("0102030405060708090a0b0c0d0e0f10 111213141516171819",
                        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" &
                        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcd",
                        "3e8a69b7783c25851933ab6290af6ca7 7a9981480850009cc5577c6e1f573b4e 6801dd23c4a7d679ccf8a386c674cffb");
      --  PRF-5
      Test_HMAC_SHA384 ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                        "aaaaaa",
                        "54657374205573696e67204c61726765 72205468616e20426c6f636b2d53697a" &
                        "65204b6579202d2048617368204b6579 204669727374",
                        "4ece084485813e9088d2c63a041bc5b4 4f9ef1012a2b588f3cd11f05033ac4c6 0c2ef6ab4030fe8296248df163f44952");
   end Test_HMAC_SHA384_Prf;

   ---------------------------------------------------------------------------
   -- RFC 4868 AUTH Test vectors
   ---------------------------------------------------------------------------

   procedure Test_HMAC_SHA384_Auth (T : in out Test_Cases.Test_Case'Class)
   is
   begin
      --  AUTH384-1
      Test_HMAC_SHA384 ("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                        "Hi There",
                        "b6a8d5636f5c6a7224f9977dcf7ee6c7 fb6d0c48cbdee9737a959796489bddbc 4c5df61d5b3297b4fb68dab9f1b582c2",
                        Textmsg => True);
      --  AUTH384-2
      Test_HMAC_SHA384 ("JefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefe", "what do ya want for nothing?",
                        "2c7353974f1842fd66d53c452ca42122 b28c0b594cfb184da86a368e9b8e16f5 349524ca4e82400cbde0686d403371c9",
                        Textkey => True, Textmsg => True);
      --  AUTH384-3
      Test_HMAC_SHA384 ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "dddddddddddddddddddddddddddddddd dddddddddddddddddddddddddddddddd dddddddddddddddddddddddddddddddd dddd",
                        "809f439be00274321d4a538652164b53 554a508184a0c3160353e3428597003d 35914a18770f9443987054944b7c4b4a");
      --  AUTH384-4
      Test_HMAC_SHA384 ("0102030405060708090a0b0c0d0e0f10 1112131415161718191a1b1c1d1e1f20 0a0b0c0d0e0f10111213141516171819",
                        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcd",
                        "5b540085c6e6358096532b2493609ed1 cb298f774f87bb5c2ebf182c83cc7428 707fb92eab2536a5812258228bc96687");
   end Test_HMAC_SHA384_Auth;

   ---------------------------------------------------------------------------
   -- NIST test vectors are from
   --    CAVP Testing: Keyed-Hash Message Authentication Code (HMAC)
   --    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip
   ---------------------------------------------------------------------------

   procedure Test_HMAC_SHA384_NIST (T : in out Test_Cases.Test_Case'Class)
   is
   begin
      Test_HMAC_SHA384
        (Key => "f16ad73790ca39c7f9856c4483202e7f8e0c8283c7d50d6da79cc07d3dc7b76c2ef76100fa3ae2df8083b5a1c5579628f1c8",
         Msg => "9870007654ebc3d28f883bb832e0b31700f923d9c9b10168e0605971cfb920e848f1c64c5f240a2cf7f412ea7a73bbbfce432eff84fbb49e52cdcbf4c36679bd2d16e064e4311381adb528a0752c8e4443d4a12b6cfe7cd406b40e3f9e9e71f42e27764649db85d99913a4628bd5d5ae49f6a5e6e9810211e35d4ddac929b093",
         Mac => "79e24a203bf42074e72c8b4a0222aface3e8ce7b4004cec2");
      Test_HMAC_SHA384
        (Key => "a5709ba5529cb9a1a227f0be448e119a356f92e13efc3463beaae46aa929df4ad1991a3964fbe161b6e5be34417a9c00eb9a",
         Msg => "4f569d60405663ffd4893777cbc37155d403e2b0f5485da42ca67503579889465198feca5eedcc39c9c53c45cb83f09daf5a2319341b3238334b5bcd8179c5f517cec14c70e6506133dee56712af6c2df2ba8a504ca427afd3632a1f57998360e9216f5040e8f75f5bffba4368eeedede54aa0bb058a43ef551668609fa1cb6f",
         Mac => "247eb51a397ba369ecba43b95a46a933cff0b1005714f0e5");
      Test_HMAC_SHA384
        (Key => "187c047e4ed5490305225355fbb381682932245b01dae04df5e456723842ff66c8905bc1ac484ceb7a35bc321d2a8619d5f3",
         Msg => "16263dd95036128119d781865e4f818a867b5066551e711f1179f616e41cfb7e82fb73130bc427093370fb43a01973c6940b776dcb1d53dea74202bc8a5bac1f834f6d412e5e587ad5b2bc6edb37a5855bada69b0cfcd6f968c719840d43a135634ab4c97fabafba47c54b6dd7541fad248a6658df6203589d31c2d5347de1a9",
         Mac => "74118d1b4c60c9dd7029829e27987f40aa9fa54b7f9c0c00");
      Test_HMAC_SHA384
        (Key => "07c64541d0cc4c2385dfc4e7f49da4396d2c4a8ddecec0583db63d7f261bef0fc68af730f780b654ac3847b490c24cfdea55",
         Msg => "f7457e98685564e3d36b5a9a2359394398ebeb2e0f1dd14d848b6245d52915c5c83481175069c3f50c74219d11abed28e9fcab17db24762f6d229f8728ec98df9b601033a37d6090e9d32627ab382fa0c0bd9bb0d6e13beeff043ee26c1e0d5f77b07313e7fb015d7071b15e7a69c9532416022287baea323f17878028263df0",
         Mac => "22e16ea2a8a7377389f23f92e1b689555015f2a5f2e3c87d");
      Test_HMAC_SHA384
        (Key => "365b145e507e9752408829c69c8732da163514b3517aa61df331e474fc2fe5c456810d2facf6838f80dee55d78103bd2f932",
         Msg => "637d2092a1f5620fa2ca9f65b1a722c9fe92307a9ed62f52d4410e9a8f90e0233328ca929c0720fc61f9cbb3550fee5f544dc9503ca3dd12391f5042466094a1f04e44675d084eda8e1e571ee1015b4fdab794cd22d39ed7d0a5d85ce8ae0d0d215654b7ece234d0b1a00c505c64b2c218385b9a5a50bbc9223c6d8f7e619490",
         Mac => "a016274a2e3202547be4f9a3830b2b8eec39dcdfd1a8ca7c");
      Test_HMAC_SHA384
        (Key => "fd0bcb3f7ce9612ed98f7ef27f0908a8a40801197c415b3eac100e040161694c62d0a536030fc09fdc8889e85a44f7f9540c",
         Msg => "2efa4e54ad137e94bead8e127ffa33bbf778461a572422297feb4e67c4615c2af1b510378be5c5905a2e0d8d24c7982ebcce57b03c83e05e8eb415aa3178007c392002ca986b2d699df9ee23ba02ef098a483b0a124aa4c548bb629cd132fc0a0f236c365b0e7ec88ff679fbc81501f36ace3c5264e33406b5e87c642ff8177b",
         Mac => "b5d46ee32b82629b49bc47f258cfd578adb86c49966bc91d");
      Test_HMAC_SHA384
        (Key => "a8de6c601fbd3de3f36fe7e71a99c8648108cba90ca38df0d89ebe34c3f1c9472e09b71f01bd5070f0838481fde40a383e2d",
         Msg => "e710f78f8a4159c802b3b5df8612177aafe301e62c68bd14b8c3f2e2495d769c8a8963c38c656d0db80172ac09c453d3780b0377b712dd5321183b2ef2be4460b3b10593f988c4c74ff0909971061dc4bb04cfe8e020158adfb1f85c3394f4bf4ace0687397206feaec6372b26a11d5460178ec111580cc3d9d652f576a62dc2",
         Mac => "b087712d244c70b4686f3bf30db4460adf065df56d874a5b");
      Test_HMAC_SHA384
        (Key => "01e5be580aa049c2eae411e93600fbb0921b6296d1c85ce85edb3e36da7a6203067727c0e4dd3afc19c814d5967ac4b277ac",
         Msg => "dcd732ac494218c4e5025da961535c1519716fd24601bd3575ac53e9380d77ed1bcd38e0d90c4a7dd0031162b3e8fc157f121448b05ed55cb4d13c25a07f21ed22abc7bbb62fb2d51d1fb8830ca95b16213f56291af976274934ab0d43805f71d9b906c44973f7d4b59b7a94d35c2220e7405dfcee98499c1c1dc92a89d7d983",
         Mac => "b0521d21418f6eceaef21f17918a8d95050e2ff17874f7bd");
      Test_HMAC_SHA384
        (Key => "0e9d0054cf2c1ce99b66cfeb80352db2c7ca6f201b353cd5ed3228a116467b3fbe0b33407dc84c45c1453e7170dec81eced5",
         Msg => "96ab1d64acad8cf69651c13e4eb42d7382e38019f3a927771ba6134c12a1bdbeb2206793fa35a4a3b09a1a8d4a0087aa0fa5023f7a2584f7df92a69050c6acd4c2f8c3cb6c8e872f7032c820bd288e1934df5a230ac6af486d60d14b6a9bcd960e5eb974cb613d801e41535e6fd44aa839ba112b6a34b2540d391de526c727ec",
         Mac => "1f5f98a2e9901f755dce5ab0e9e485e3a53c87d7621e7fad");
      Test_HMAC_SHA384
        (Key => "f755ecfe7773f5fe6a044b27ac3ed6108ffe98092ec69845fe011f3fa68f2756117d11bac114968c66160041af449a486023",
         Msg => "fea931efe3ebd8f719a6d9a15487b9ad67eafedf15559ca42445b0f9b42e7089cfbd62154160cd19aa086eadd12e6ba93b148d0cfd4da99fce7f5fd5606807f6f11fe97c1d9cacbef67b12cb56fde2997450255fb610943fc60d5228e84fd7fb8b572cec1da85e2c24862dc58bfe04c539262e9ee9a646cd3577efbaf3ebc6df",
         Mac => "6f08776f8d86fadaf681c32a4f7b7cf639a7cdb5f8dd836c");
      Test_HMAC_SHA384
        (Key => "79c92036d1d9e350978b077b993ffab6e59f4ba997281a44efe6cea4a77e06368372d11e29a121da330d7d2283e1f713d6b3",
         Msg => "a62bf0d3ffaff7484b0f493517357cee3635a444097fbd57fe5849ab578b397e2d5b1159b4bd48e6c0c4ed01885d9111aa3c60997016910a521101dcbc791adc11b4fac8ef78d119b53b8b2042ebb05400e088eb220f82a72980d6f3ad026a2e5a1df34739485c8a305c6bb9cd49a25f3f076361a5d058d68c8d1218b28ef01b",
         Mac => "6d8915109cd5240f4c1e44c5b303aa1b9616f3a256742143");
      Test_HMAC_SHA384
        (Key => "314c2ab1ad359b1f606372aeafbecd98415c39c6a89874874364788862e0b401ac2b9d2cbe7865fb15650a0a2e8993d3eb4c",
         Msg => "557e8462a2446b408f2ceb5e9ff9c546c91bc072298cfc57f6f883a2b42021c1ab8076a5972f49c6a1081f688e070c1d37f5ca8c39480870ed4504e49b675cddea0422f89b2e2e7677d8b884863926c0827622fa8b7bf0371c29fefc3eb7bdc9fc52b0e31607c356fae3dd3bef59b83794e3f14489ec5bb46cee997307d8ec8c",
         Mac => "e30f9c9e38b08f587b79c8a64ba5e928eb6743329055ca79");
      Test_HMAC_SHA384
        (Key => "865aa6d8aedb7a9de1fc289b0d42361204891e652deba11e79e35f3199b2a5856f0286b0c2ca2d03357171c67a36aac4c3cf",
         Msg => "c59f8dc2db55c453c403bf91bc44bf882f27a76329d40a320e7389ea8b495cadcc242e4cf0fa2e0bbacd63a489d13f8e8ad1787e2ccf132fd4ebc25fd3866f1a95a6193a1a9cdf2faae55afcc54f30825a5ce60139ebf6dcc915229cfe56073886edf5944385fe47fe144da15a04baed06919bf33772dcc156bb52abf5024c91",
         Mac => "1e4f3de118bc66b4f15e878655d902d51d3ddec17b5b6886");
      Test_HMAC_SHA384
        (Key => "c64a74849e9c2f805d89325b5f0472c6e36ba91d2514a199c72aafc775b77d39c9010d7b6c1afb487fb303fe3931c250d103",
         Msg => "a87050f3761f3d88e5823f3dd3d1439fa7aafddde157222df650d86c5a006b04decc41133c5210caf0ee4e134a83e976c278393d8b0033d66b9fdf7ac9ea0c0c088e42441393f80c39e2072a3c055f20a42ff850597c0c64717984ed47e7b04acdbc3acc236b5d18686552ccd0e00b65f6d724607452179fb2e7af0ffb81bf88",
         Mac => "c26a8cbc47f328376fb6a315206ffa5b0afc8ef2e7c007e3");
      Test_HMAC_SHA384
        (Key => "4ebc24048c2d89ecd39db53ab1e85ce317d28cd118b08e35ee650d1f3e90794c9d04ae3e5279d1925d817b8fb9bd1afbdf50",
         Msg => "acaae447da1dd1ebf0167788ab6c1fd2428a58b14ac4f539d7eb55dce51ee7def6e4ec0afc787fa47864d39ee451bd0e4f1e72e0472f91c8fb08647ba11a631f16dcf900c41e8b84c99bb76156cdd90d5405d4774eba0ff48b21bd7c7aff621654bc9291fcb8fc752ae2a839c8867db69c6606dc280d76a4ce60e9453876ecab",
         Mac => "05a0fc70e839f7697d8e9a2ca10939bf56c38ed77bd9b606");
      Test_HMAC_SHA384
        (Key => "c2f2f7985728b677a7ad062dd9605a2c24e7cdfa86986f35b99adcd4634714af8dd5864256366eade83c6100ac0126b6ba86",
         Msg => "35af2ea167e56c8421cdab1b9fc99be4b85f74c706d43a4947fc3f020350e9517041b54e92cc7c00a64ff6d1c19b7c3eb54a12d33453a45738db9044a14e657a20afea33552c633a34f60f58ad4ff50f8ce5e18b9e5ea9d61534b44b2dc3bd4d10a0d539f72da798936a009aab0e8fc006d7e9d88b1ecf2ea7aeb401efd67a34",
         Mac => "6e49e4aa01da45cc5ffb71569f257ecf114fe858ba9590afc23afac9c0d67f52");
      Test_HMAC_SHA384
        (Key => "8f239b06fc6678be26307dc702f854f6a3d0d980f6457304af87a5cc83cae05098eb9cfb3a57a732cf29bc930d92577a6a7e",
         Msg => "35b127b52a9b4aece978ad17aaa700b547b17eab59da27819ef650ce9f7e5ef18fe3cf0275227a098e99176dec1901af643c3b57a7f9b12faf75c1b05d1cfaba60f12488582280e23be05194f86d9a205b772ab031a4d64eac6e06570931732d6f822e2d1bc3e5e1baf4627616cc5470f509529c3e041d465e8825adeae44fb4",
         Mac => "4a13783650cb96aa0dcb4bca10ec30ee2a9d3768f2b6f1dc626f99545efdefe6");
      Test_HMAC_SHA384
        (Key => "299b37b8a63c49e53a6d2d174a9203028626b1ffb564ce5eb547bffebdb51f1ce6f76569ea6dc05f2b8046d4f7d74ed00ace",
         Msg => "8c886d5c25bb1ac4e1e8ac0c59da0d7f746418a47652b7cb39a048e6b9ea469ad7242596568b7d242adb6bfdf2c33562c3962c682743d79465874da70361e3bb8ac7078f89976c20dcd068792e029acbbd03cfc05de4260dc0237347f422e2f72dd8ddf0c5c72fe0812e6926167f84e3ec13c954211dee5fd1dd826b95168b75",
         Mac => "a38e187371f1d2517aa4639975e1d2115c288d22968459019f8c7f8623254268");
      Test_HMAC_SHA384
        (Key => "136933635a4f9252a65ecdb0a266fe7a68e935d597db26f5a6a61e3d78713ca830a2dd6746a158ccdbdfec664918f66effd5",
         Msg => "1cd86dbe49225fc2f82758f53dfa3696ef66a7645dd284a93d686177e5776232be15504ef508eb5a73e7823e107cc2c1036dcc4e9d1b8af738cb42ba6a046b037e37c07324a694e0677e659de046b3fb297d120f957f7fb61ea9f0d79fbd2fe84488e7b43ec2ff5bbb35289a1522b24c49e0a431acc60befd94b9256ee6c53e8",
         Mac => "3e92717865123dcbc7be18c72522aad889c29dd2afa16d30f0ad68cd9640bc84");
      Test_HMAC_SHA384
        (Key => "ade0cf1adfd3a4d83465721f9002c9cfa1ad70220794aae3b9e8b9dba4eba18d954b2e2358ae38a7228e26762c47b1f2a16e",
         Msg => "97362855760a948f87da5dcf39a888d0f194c75000ff045bd2ef3ecb67b5941007ce9f2d32080503d7e54bd2c644ebfd663ea70dab4f1cf943b69aa5101e33a8db7d1252473d0fee039a8044444b51627364579c227be1d2450990f19f1469bc7a0b29cd9bf2d8d675bea12d9d03e1887ecc7e054eca7a6d41b2c8b9fce05ed5",
         Mac => "2eb416c1063b6da59838f3a6077eecbde42e4cf3d0f36723122e2d8794128703");
      Test_HMAC_SHA384
        (Key => "5ff06d199ea158a07130d2ff2ead78eefcb74313354a0b790fd9493f7c9d218d4e2ca0cc9f4d4217700bb7ec9008e628c014",
         Msg => "51555f744e6369f81b30a4a0514486df254f1279e0c7f1438fd3c32afb68b777dbb1595249b5ac847334798193d1e6a521774abe46f540cb95ebfb03f6ead919e2d73abfd690926901d2bd53405b93c54d4bbd9634d0c7ef06027551d00c5bd9ce8da8c3dd3e432e2fd4191e4228b5c7139511098fa1ab374ae0dc1c73166540",
         Mac => "3e8de7498a8cbd9df8dc3f5dd825b0ee0899e226cd4c7cce1d3399ab9c558fa7");
      Test_HMAC_SHA384
        (Key => "7a136c9d47c743887b92ebb6c5792769b0e8868dcb479ceb07cf93a0609ce3cdbf035d911f256e34efc4a2a5b85667270058",
         Msg => "402aaa22c009335112abbda48e20e9c4828a1c131976839d816d544c4cc5575b17bda60c6acab19ee02b847988c34dad8a28189a0ef8def0596cbedb392f8a77a470858a9c366b7255f3b25c9a5d10b76d793de9eef8fa407ec7522b23e220aa2e69d1031cf56bb7bb2cceb48e933bcc71a412668021e07336a798a4d28621da",
         Mac => "c0a992be294eb3414e4603e213de66b4ba8af1f10c602cc126b1a5a63ca008e3");
      Test_HMAC_SHA384
        (Key => "a03fe1eda0f4dceb1f517f17963538fcf913c03ded53f01e36f5d6466e7808c4fdfa384f45a009d21d382128811d7f23875b",
         Msg => "a2350856c94b669d115dad9213f54fb0effe9adc86298cebe990e865109a8988d01ef79007cb38361ac7e977a1968d96603e24647aa800bfe14ad45911030ebbfe4666894a7bb707bca20edcee3a01164561436f263c75ce67993e1104d39d0a14f67ec7fb248c17e038474962a8563786b01e84f4ad932164c74e1653d2e17f",
         Mac => "0d0767dad7dbafd8174d1a007e1942af5a5c4e1fe7f85c092b446ba078ccc7a0");
      Test_HMAC_SHA384
        (Key => "02c1ef58b09ceafe3bc94298c175bee5d875307c8b369d60a0f79ed41d3506710a67c57577ec0d5ec142b3b81278d73327e6",
         Msg => "b25347513090a731d128b0deb2109986d4948a7dd03ef53dc6f92aac9776269d54cfac98f66a98de4f216fa8409f3ab02d0d95f2aeef03b4874884c4db056a019c98681c46e4eca0cd59ae30d36089101ff98be84ba248c4bc7c735ed8a9afa072f8a26589c44b80331996ffd4192eb1939e93e50f216c754ddb1e03f6299d83",
         Mac => "a4063a744763458ca4d03ae156394a0443967b2c4df3bf111be045e06be7322d");
      Test_HMAC_SHA384
        (Key => "177470b4f10e6e95f548296d9b0fe73192a3ffb0faf6a71cd45507c6b7499229c4c0952adc68109e105cc60d580290b58833",
         Msg => "e9168c659c63b6f40523c90532bae743f24feb2e94814b6df2554365af73300abc933af5213235b8fa89c96ebfbfd196c95e02211204cdc93d5b86a5d64ac5fada6d0d557ac3abd61ca7e1cfa302448ef0be6376a87ea955388c85f11712c7e44b8e4eaa2f80e0f97365595064e908d36e595656df57a8b8edd18772fb34ff6f",
         Mac => "2b9910ed9f3f57180605b15f33e95d4ef40b09ee7ef7e71340cc4449c35ed86a");
      Test_HMAC_SHA384
        (Key => "be7a9fd43c1e987ad10b0ca6f3ecd067c961d286489759b89c1b8d17c9f039d392dfd0259a0eae85c9d4a11df1cca87db128",
         Msg => "7222bc21c60c8b4cc2e4e3e746964a70a7b95440b079c519e6d4f6fe100a7a47f74e00f46bc27b4286a2817c35bff114f330d9f2d844970cd3bb3e3734353b3c6dea382f199c40fc3dca2443ce271e66744ab5e08ea7e0d876be6ef50692a5755b5d2a79d88221a36ec394e31bb4198eb16fafb1d98aeaa4574650e290090217",
         Mac => "15f3f5e9d459d1cfdec6f183d162ad32bc93864ac7a5ad9c40d8efb11e327619");
      Test_HMAC_SHA384
        (Key => "d7d2dbbe4f6574402121e53a88295b7a2e4cf2f342ce70aacb6b33d33c996836480e7ed8f782dad8fab6cd973cb5c31bb959",
         Msg => "a927bfb3d1f4c0b20fcbca263af59047bdfffca8ecbd215e988d7264e0e0313e4bf72add14eba0c3c5f0886707daf5dbb9e1d4ac3fa1d90a1d65b928c4a49ae6abccc7aea23fa99b649bf3e16b3f1c69080b12bbb2662d219f86610991ecb9acf32d00ed24f8c1841355735b0c2bed38d105209ded1504ed457ad3cff0be76d7",
         Mac => "43f9dac7fb0f505ae19400b4c74ec21e352bf907a14f9927a0e78cd5ada3b5ed");
      Test_HMAC_SHA384
        (Key => "a60727ae52ecf7fe66e99a8aa3c58879ebf141da5e1792dbc2f5143c286cf703ccd4fd703e93c933bfee5addee1fd395a4a7",
         Msg => "8cd3b3e412bada22812f7b81dcf7d6937bdc21085ead7bd1c2872185f253e4036090db59f45355e4a48b11b9458ab244a0c16d2fc9cb0585acaef918e95dfc20e281a5241178681ea09ec5da33ccbf9f091f901143fb9b56834fa278b91a390a3a2e7a0f1334fb179cf0fdab50c6e6ebdb7df2767544258a6ff2846d0b92840b",
         Mac => "9da04e2dfcccd9db25c9f8566879c0aefedf0bf7a934fdb8ff7b8fdbb0568a04");
      Test_HMAC_SHA384
        (Key => "73adc132087af20b6ead6ab3886c412f52986af87109e45b0f1b3420e569126a99d863de4bd867076be634f9cd556335ff4f",
         Msg => "5bbeb367c6a6bb49682556772657bb9817c9d33e953cf0c894a6bc87337a701f91294630e2e93036c2b5caaec8958d7b5f1f4687d13ec7ada532ddd72bd88263552c53ccc80c4486333f9229e0b5f9d2891028c66c647259a13bc60facdde1004fcec281a2975e0065c99630944066673ca55f448e36579431ca5f76dd0ff5be",
         Mac => "12153d31c6c4b874095ac70bdae80b01528d86aa64cdb7ec9a169e5dac2eb0c7");
      Test_HMAC_SHA384
        (Key => "6dfd83804a57e35a1247807a0c828e54b32eea5f72960169ac23ee2dff88e227ca3cc9a7ec2d2a25cfb34fd4a6c2a779f265",
         Msg => "0e9913001b537f335e3cf67ac5918f20c01ac83a5eb8cbdeb33ef0907c8182fd06b3c6ec4bec39715e0a1a630abb2811b6d8ad318cf5bb19db36b632b96412a9ec3f5e670b168244e096457711e01251ffdefb2cefd6fe9e683f87f2dbd437d88ae8e45ba2f9e114aa877f9d2126d34963d3ba12cd841bd321036cb82cfb78f2",
         Mac => "cf51592da0cc19c255abda08e6f460e011556f73b5ac0add69dc46e8ce644fb1");
      Test_HMAC_SHA384
        (Key => "1ce7e20abbdcd1154d4b536714ff534a01b8e88c78da34d653638c39291fd80ad01f3df02067fa3bfae7907789ad2641c858",
         Msg => "7cd750b5c9b2bbc3ee955a4f4fa7c956846c8b1b52eaa06fd90a5a300e426c106c714497e70a9b6c22754ad0e1b25f6bc140704b273d2f2a76ce3fef85c1467850714497edea235ac24e8f90f678078825de341c58bc7aee346fcef2711ec72d8ea0f7bcc39a7b1738e8d197743fea3618108097cdafaa467bb4ae40bca216b6",
         Mac => "729a167f1986cac53ff3e111ff82f2a77b573d0863e1a3aeaf00041a03e1430188a202bdb7e9bfd4");
      Test_HMAC_SHA384
        (Key => "362bc440e5dac16a4369581c0cb5be45bf4f170847873d6cdbc9bd55232d23b39c4978f93d4a08d15b43690dcac4b8e145af",
         Msg => "1af3aedaa8fac55157f30642a00258102dbd482198e0f13476411ff59406b4ce80154a014bcc19f48ef31bcbabee6f3c5537fc9f530c56458065e50b1729442f2da1e7627f2d011e6e36a43948632abbc910d5ede2fcb2b2b841c31af08a5c352a80ce25cb85437700a5e9b400c95332912e1c30cd16cd2226be004aa88fc688",
         Mac => "6467e5a690bd32e157cf8ce674ac630b74ce32a78e8f78415346c00c3060a4a26c40c3e2eabd80a7");
      Test_HMAC_SHA384
        (Key => "91a8c08f4f34073913e540eb276bacf07d7e6fecf317f2b8d5e1866da3ea4abf159f4e8d5df7f8b5aceea72df7359750fb28",
         Msg => "6e0bf8d8716cd86b5b00652a308be299715df023eed305bcdc201bc5274da5300a7fc7e4dc79c6632d61beaa11c79359bce329134f1ed828f2d51a712359877c4d3a04e99dc5371411cb3ef5d2a4a044c37483e05aad2071afd5754cd28a399862c315af5b5811c730c54dd21a2bf1a3af976651b687c7e03aaa921edde8a4cc",
         Mac => "bad0de1a7ab01eb36a28a67d0a9488a873a82770d5a8c30e4253e04af51c31bb131da8aab4ecde2a");
      Test_HMAC_SHA384
        (Key => "31d63a82fe80439196ad230542cf8c9474deb07b00b20f0b88b08e6538a8ca82b4feab764f083cf57eb8ba168c7beb578f60",
         Msg => "4e9d424c31a7441f6d16d41caafc861ab8fe3c002d66ec7d5073a3f936f3cacb2b14a9ac5478296b9287dee3a809442ba1f4490c6c820cb8ca87e5b86a02a52751f21f1e806be76fd1e8599623e3ddecb6a36a1ed85649dec25f1cd8bdf11ee889ddac8afea80592f4e14e1d61b1d9c7c1b4a61ebb072a5701a3504078e9be76",
         Mac => "00da1f3b95139c23cf91730b5aacadb0b6c492a6b08765ca7949c315a792d86bef38e7a747486cb1");
      Test_HMAC_SHA384
        (Key => "917a698c82f44f19573b645c4879b8730b58dff4edc6a0d321f5f18658a5246692a55b59339741ae59f5fc486d515dfff8e1",
         Msg => "f51086fe78150fe48bd1415a4785acc05ab80ef00b2975ce7807a4212264b8a1ace80b50e0c2590ef3e421680a704eb2fc6d17555abf2469ad56f287fea578d89c560b72193c7fe596898f1040417e3a1beeff5eff9653c5e0eab1da52c0ea3b4bc34d0c2b69c890fb2651faf2e084803ea28eb20194490a992ba8c4249d56ef",
         Mac => "77bf5615ec52f706ca746401e9fde43f15605237e550b93a8472fd144fc39e5eca0fe890838828a0");
      Test_HMAC_SHA384
        (Key => "e3edb229240030c44ecc34c855c176d8db48d138a7615390538a90ec44e43b06e091f7c8fa606a0d91ac93a8bb815ea7dc01",
         Msg => "5e56f4bdea787d8e6f434fc114d2647b3f86ed3458b33c0ad198e05b639512929a98504193d9477105c7f6367e411186ef0aa34a6b77f8b62c6bbad6d7855a6a0098b1f4f15ce80fa76395021e4e2695cf4083247693eff118ca2fbe45c7ef9c9b3f61fe8b6a271160ff73507c5f6d53e510d5e7016ee9649e9d893b35c299cf",
         Mac => "12aadfa5bcf4e356330c99c65edd086745e113f1f05569d9ea699db349fb3e6be2199a7007ad71bf");
      Test_HMAC_SHA384
        (Key => "d5728055ceaca4b0a0c7dea23024dbac4a735c2240c9f2ded4f2053558081b2a144457e2e8154058336fc552f3667d942dfb",
         Msg => "96bb91b01e68ff49eb74bbaf26b94a269436c1410eb1d7a431a03e0d564a3496c42a55342594b384379b28c7c431eb2ad490624c21d937facbfbae3d4dd73696b0a23e88ff8a4957fa9c45100ee518c985d77d2afbef0e2c1195a1216544d8f5c1eaf4b39292ea4a9c40b992ed1cfa8a0fd3b9e4823b83c36936c0c384d8443a",
         Mac => "798429b7121b0f1de65c702bba78f51c142b483f96a4dcf12a95686074c1dbcd7d2ec6dfa1359baf");
      Test_HMAC_SHA384
        (Key => "f54e582e3ffed931e05f2b20a599218fa201118f76473480d1f04f2733079301f610c2d68e3e949010e6594ef132dfb5101a",
         Msg => "f5d2c18fc109854abfc47f1f39acff2f9b116e4f3594315d3d23d1d5132b599fc908002be3c108c05bf2e611e909a31281b582091c9ce3e8bb4d67daa975551c01553d0e7173db8a3d903d7487db2892cd64b99eb3d3489a035a9164f2e8168aa5a0bf5ff389c44f6d87cc6f9b8a57588905593682a2271c1c34979b75ec6392",
         Mac => "adeb260f3a38f1bcd2d85f03cf87ecfd4c8a6aa1820e132e87443a24f5a3f8d87124236cde9dacda");
      Test_HMAC_SHA384
        (Key => "6d2dd39eb5fbb9410e6652259c5402ea0a14e70a7b896a1ac48b144cd88aa43983745edd5cd9a5e3f54ecc23540f2a6aa7e8",
         Msg => "5820928f8ee262201abd8da3c07a8f38734a9dcbbea22f8b6249bc9d41b0c4117a811415d67a4668637c87125edf9d53560928d98f3f2735a5babf9071fe389a306749c4e20595aff1aa75e41340f8c5716028c409218fd2512efa1a1d1c7df0c2fab7047c2957dc0d6edf81a745a9780c7827f3f4f16e49afccf6a40bb19bf9",
         Mac => "f59fcfb65dc73bc3d07118f5a5d7d0c2b6b0f61e3f21916f53d5cd6a56307fc1f1f8c5f8349a3b19");
      Test_HMAC_SHA384
        (Key => "32c0e6b478d33958fb40580bf369ec64e7c853d7d187e9e47d4a878e32504a0f94ba96cac92a5a81db9095c85d4119b9524a",
         Msg => "1b5cddfa796d6956a181cb9bd2295c8b57d9d2d4b64a15932b1c4e1754c040e72e95db0640510e7516a3defaf117b520bd39fc7f43fdeb3da05ea0d5f6466f1761ae7a712d06816c46d7fb79efa765eeb71dda4ca965e4c3c4d692f8abd2ca059deee1c1a653694317654aa135a215fd2ecc94c3514aa62c7dcc4907da2ef9b8",
         Mac => "cfebe44a614233360911ff1c0089a94ddb4beb91e81209f71419639957984f13ebb123c6e16010fb");
      Test_HMAC_SHA384
        (Key => "c83ac14c3aefc2264e0ca5120e806a9d226499bef58c850c135cd22dd6dd359241107b612c83cdb3a1213200874e55d77d34",
         Msg => "f03c802de9dc4148c3109b96fe2d1fbac6788ebc10e991f4e62eaa2afff36bfb9361e67e6de4642842325aed418998a8eb37c4bd256007fd8cfc06ca081f147ba47da5029d2d06cbb8ad4ce8d9278b6cd2f24814795c302dfda70ab17a51eab4ca99a7fe9f3e90face8a5bcfee8f5ecc22b102093364744be2379d297c12556d",
         Mac => "e24da31c2549ec584487da6a78d8ab43ceb65b013ddd5a503fdc58dfd5eab0333a4c8c15ea50684e");
      Test_HMAC_SHA384
        (Key => "4669d93298c70519df3a12fb618216a77b15f57ce65ccc36391e9007af3df2ea2ba086347970256bd787905cb4255568b7e5",
         Msg => "b63cafb63001021837a13e46410ca942d4f92b2341cda5148ebe849fb438962c0b7f1cc40297201b136109cef6066ce9159825ac41f7a78fa3f29083f5af817bf24d2c2b0ac7ae0f5b1c20b0ddad6823dce655d2ac20ec7f98c6fc851bb7f96153ec0672b25b54fdf71bab745cc846f81129e41cea101cec5582f12e8e18a6e7",
         Mac => "53dbb4f115e1cb292440d84d583ae02cf07de44b481f65438a95a14b72a3413cf5763b86277adaf2");
      Test_HMAC_SHA384
        (Key => "27a50a6ef6f71e5903a0ead724b587afcc69a6e1d1c973f173aac0839bdf5f2860afcf78cf861c61ecea00bef4b14e2be571",
         Msg => "4e9a4f18f6e00790ea2ce7e6473b84e8ed7d649b2524bde5887b7e8a1c7a935abf9765a8c9dea1fded443b0e6039b2ec3d7c957b29334625333bfecffdbd110c21027491ce887ceab255e86b1d8b2268633dc2a98281541804c65bbd276896ec3c8281bd4d041fbd0205f7e3c55a5cc62567f20c78356e26c5c59d3be1a4a861",
         Mac => "8c00cd98e39787a5c91d20777f1a8bb4f0bab8ed8a3a1698805dd52ff01420459da0011ac4d1781c");
      Test_HMAC_SHA384
        (Key => "a6990c41a94ef7a358fcf1e05dfd02b41193730f33cb2719e0a72f73bf7b98c07d9887657928898cc059246f3bbeb2d327f2",
         Msg => "753e66d2913bb74a2d9b3b112223b6ab7217682781a2e3a482771b142fb9bc40bd19c00d0f3e40fd2a698af8e959754df16cf1f4e808e216e2392fce1c9b1532ed7bc28df9391fefa8f0ede8d7591390cded36ca704a8bcab8d8e9d565ac2348edad94dcb9f5fb28907a8a6854ed397cece26034813285caed9d72b070b48b8c",
         Mac => "2d36562d9dacf9fe8cda55ee2099e2e9c18b8c02dae8a235aedc4748d68d4563e0d93c420e2eef01");
      Test_HMAC_SHA384
        (Key => "038bb8d2cf699af839d597806b2247edec8c830771c1d580f7a02ed70e40d77d7834aa37f20d82c35221f0bed28b30c5ac73",
         Msg => "32947d045f6c1dee7dc055edcf1a957a7c536ac488b109f603532cb880cf1cf8c9190fead1a7b54dead20ef138807e766600235697356626a0f7d01874b620c5df609a297885a1efd1ba88eff03ba6f603d4a8c54f012b5c6a548b78aa17f55add33c4ca3a500a5c983e6cf2de933482bb96a119975c8120c93102df0a3ac63f",
         Mac => "16f50fcc2e87a8d525c4402d45146e2dac1f9e9bb4725aaf90c7df008437e7411974e15b169d599e");
      Test_HMAC_SHA384
        (Key => "5eab0dfa27311260d7bddcf77112b23d8b42eb7a5d72a5a318e1ba7e7927f0079dbb701317b87a3340e156dbcee28ec3a8d9",
         Msg => "f41380123ccbec4c527b425652641191e90a17d45e2f6206cf01b5edbe932d41cc8a2405c3195617da2f420535eed422ac6040d9cd65314224f023f3ba730d19db9844c71c329c8d9d73d04d8c5f244aea80488292dc803e772402e72d2e9f1baba5a6004f0006d822b0b2d65e9e4a302dd4f776b47a972250051a701fab2b70",
         Mac => "7cf5a06156ad3de5405a5d261de90275f9bb36de45667f84d08fbcb308ca8f53a419b07deab3b5f8ea231c5b036f8875");
      Test_HMAC_SHA384
        (Key => "f86902e5e5db478ec6e278692728a812c4cd8745f90a7d9f7915f5a94345fc12d2770a3c94b01ffb9e0412999eb6261d11a0",
         Msg => "e0bcacbe96dad6f60e51129f35acd03e12276a91fa13fc15037c75cabb0aee3a19253bb8b35cc0e63208867a032c8f4150a066642f6ff9ea197dab7e9d6da67255c16e051a43bce174a489e85464693006f11a4c61135dce4187040937eb4d1c7eda6e2c315771f0bc6f4273911a07151c63afd3f8c8cec963e4a8f5ef4b8b3e",
         Mac => "4bb4eb2db2cc921b159b78a2bb9edc1608bb2a1ca9873b411ae30a63386e462f9f69d9f5fc838ff1818748aab74da94f");
      Test_HMAC_SHA384
        (Key => "0d729c7e630560f8e8dbeb745e021f1fcab754bf6c8af0f4f4bc37bdf3ec653f90f2fac27c0c56fd2838859335e05cdd2cbc",
         Msg => "009b71ebbb05a82c8c13388f65c4b3b57164c5e5ed0eafae3970f7ce2fce5e53b34913008b6226f272ba3f84671b906f4bbc0836abc1cac1db02dd47440d2572fe6e92bea22e97235999def339443a05d24fdd1303e8cb6113108e9ffca22b110a9156eda571e2056b397ba5834797bf2da4aa459d8a99d70923729e01945a78",
         Mac => "a7d1b0081f4884bfa7b30903251fa2803d96822a2160772a473568d41ed3adc77c1b4950a22a14ef5b335a2842046cf2");
      Test_HMAC_SHA384
        (Key => "5405e1f28569138976b03675efcb88ce373e92c84080fe381ea0a853bd2ef8b8d4596eb115557eb5a7009f32d5c49f8a08bf",
         Msg => "3a7f4dfecb333e44f0258d33d69ceff70ac07e948f5c6acd2ee3ec450db17ce48394447c2b8bd4ac37cd1705070d866cfbfd9bbf851189bc82852a1ecaa13908053cc1a7c17fd514c2eb8277999d027279d132bd45a6470ded21bc3bfb738ea2697facc9b697a9423986b5d1b4d4cbd12c452cd4f8a30b8a19bd8ae4c9b0e578",
         Mac => "6cb9ff908bb72c45f49da3f4a8c5265983c1f4d811dfc098cc3ffa58aa6a6d0ba18183455cee62992b4c3a6cb53c5c16");
      Test_HMAC_SHA384
        (Key => "6c075056122218f595bb28753e87ae6334a0adc24336e85bdb8202545cfce30490ce5e067988108c4e158bf6c0eeb4a4818d",
         Msg => "0b9b52ec0e46793a179589513f117a956fcf98717339373f5010a268d8b254cc7b996b6460255925b59bdd28436d320945bc868d7a1bad87799617fc45f3ff852137e6f5a56c403c12a26d8be334eab9a44cc9e607a95e5e35a03cbf6261605fa47cabe805a49645d7b221c247ed0c6e35884ac4436cb38b2c38f9fb5886dd21",
         Mac => "58c6f879aa6ee523dc374a01e541f02f4c3dffb948b071468d2b242bbd358d8614aa7fad660348e61828cea1b758b91e");
      Test_HMAC_SHA384
        (Key => "d137f3e6cc4af28554beb03ba7a97e60c9d3959cd3bb08068edbf68d402d0498c6ee0ae9e3a20dc7d8586e5c352f605cee19",
         Msg => "64a884670d1c1dff555483dcd3da305dfba54bdc4d817c33ccb8fe7eb2ebf623624103109ec41644fa078491900c59a0f666f0356d9bc0b45bcc79e5fc9850f4543d96bc68009044add0838ac1260e80592fbc557b2ddaf5ed1b86d3ed8f09e622e567f1d39a340857f6a850cceef6060c48dac3dd0071fe68eb4ed2ed9aca01",
         Mac => "c550fa53514da34f15e7f98ea87226ab6896cdfae25d3ec2335839f755cdc9a4992092e70b7e5bd422784380b6396cf5");
      Test_HMAC_SHA384
        (Key => "5f76d094bd102281900a1c1973a1d7a6da880c85f8382022e0885d24ea7d83e458637f24391c7afe8eb9151aac47f324e1eb",
         Msg => "07b2eb870ed51f53b01cfbe9b01469d96f69f7cc03aa8768884b4774bbf0e43dc5e9fb3854f8d1e8f05b43028d0600d05c31f5d3e71209ac5dec0b3d2a48e80bcb8222e6e1887dcd84dffc0cd9e70ba7e75ffefba62bbaa35955b2991e53169dc48846dbdc0d8dc813b00c4dbf3df427b7fdf98e687d0314259026d1bf97d4bd",
         Mac => "9891feb5bae6e7f517783322943d7074275f405e54412f3f27ab11f5fdfb57bb54067852789b55dd21107c11a809836e");
      Test_HMAC_SHA384
        (Key => "e339f1caaf630eea2e88fa5989bec005c780464f935d2e6140edfbc20a0975279f3b4e8dde740584defd0bce32b025286b68",
         Msg => "edd19cc1f4e6185c362787bf3cc3e93a2a21990c4f2380cbf9ad88068e615328d8ad2e9fa108403e807807e0f258064fac58b76430c5c76f9f0b82d8ce788d079b42d38282ccc1556b25b6b7c6d1b5eadacd5e635acd1c2b3ac89f85c0b68dd1de9974b0bfba0469a0357b8ce1b760d55c877452f5c3e6c872edc6548ea6bc4e",
         Mac => "af65cf67f4b82a1f1ef5ff3c7b99266daff3e134059f5ff26261fbfd6114f13d69c1cf1195b93cc9814255ca9a3e9267");
      Test_HMAC_SHA384
        (Key => "fa0f033f3293389e5a9312c6046757eee20fda34e4c8b4d8a1ddd2a8f8c0b0bbf7596362fb9edd5c19646d49bd74856191e2",
         Msg => "ab6d18f2c0756519657eab694e73f35969a324c279d0c994008214c863a12395494383e744c3f30db3136ab1e7535b0e84a2375d2a34349055a44d43828c89f09454816275471c6c00ec9eda1f93e1a8302ee172ae627f2c0dde7e13e5ecd2e353451a4b9d2a6b9e14b04fcb3f5c0d8f35ef2be94b8332cfefd7b11fd4e884d8",
         Mac => "b075d10aaf54eec1a14ed42d77a9d961452b480bc6f655995dbaf7acab6befbe7bf6945fc0b28ec1898b3a912b539a7f");
      Test_HMAC_SHA384
        (Key => "19d7b971259fdbdbb4cc0977adb704917d2b3c68b97796df05c26d75349fd777b1e229751db1bdf239def25f0774754b2c8f",
         Msg => "5ade9519477fbfb754e1427586417618202ec140cfec68ed2517a4414888f988ec7dc3757ef312aea257b78ce05e9f1b9a32606942ce12fdcaab60a55b9cde7549f69e0c47f5fe19d75bc31e055a6c7455b4c090fa21aa8448f146c86cf23c3b5b944d65084b2bffda358eb55dfd842a38ff083d5fadd78b89317f34e554b9e3",
         Mac => "b50fa5b15b51f7b9eace48a79bbf3e392150fef2448500e56a1b25cd5f41b3b159872985b67a6170503e0ace217e6ad5");
      Test_HMAC_SHA384
        (Key => "f915e9a8a822b2bc5e67eb34cae85a5178118afff44a130732cc1b862db31d9ecf54ea6b11d0ed3863eab2f34e15aadf58d1",
         Msg => "9185eaa99394c63ca43f67b663c0f03ea998aa85b1264bfc7c79794473638ae54fce8e4436538fcf2609177b979bf3705c9e3702cb2182e41d858398188fbc2aebbb861e59d356a719c13e1a7da2b7a1531b9d3409f07bc514d209bb9179f3a22df3dc21433ca32c450ee57a5dfac33a54b8e502b2bcbe0827091294294ab6b5",
         Mac => "c19115c8ad223d0ca3e2eaf0ee5bb33900b29e9a8bcb3d93b9511f3186b2c23e4dddd1be36cb4d43cbb40936126f19ac");
      Test_HMAC_SHA384
        (Key => "35c28f3bb2ca3a2d3a5089df8b6f3ae27af3f9072dbd31d98a6a216aef2f3253240788f68e11d706a533784aa804bc9d8fe9",
         Msg => "268a1505739c34e36179ed0b316a33311cd89a28f361189c032b0d033b7882d1917baeeba16bbf5f97d5d7525036543abcc9544d879e7838f8ece91519a899971856cc88ed20d6763d2526a97e1383585df8961c5c55a9a4c075aeabaafc832784c374c39ee302901910e2f7052949f3c60c677dbcaf3147236d64ac379dc7e7",
         Mac => "b5385799bd110ac1152146e295331f3ff5c2d676765b933869c9b507e0715f73ef00dc42807e2e9313d973fb114f74c3");
      Test_HMAC_SHA384
        (Key => "c1a8b10b8f7cb5ba8e9c4198b04176cfc70161c8eda3809b233282ca38504f2eedcd48315678d03e83350b766050e5a5da11",
         Msg => "24a5551bf8c75913467aa639ee6f3a6203c0d8167dd45b942e824b15f879ae553cdf205095382649c78ac011f2be3d860c4a535a8d0d6f166c7a4a5e4bf9bd76ef8ad605f2ac2b19bc7d6e6caf2242e6a2694d6291ad8fb592fbf2ec0b7222d623f09ec376eb108a0d9cdad18d63f188ae67eeb7ef7d627a894b6a49a1ad847d",
         Mac => "c4ab31ef4d7b1872a0f926db17ef4e4e816c16815d7163566460afca3dfa3af3c6846eb1f6e9aaa08dc14754977b08bd");
      Test_HMAC_SHA384
        (Key => "8c185fbb4055ddda5111172aaf518688cf85727343c51d718e5a3eae3680b0e71b6a6c860687b50f850492baf7928162e369",
         Msg => "935848ed0f2851a4b225e6866d10127d533f21bb9e95bd4df3b157f3e766c92fc16b399c8154408122c14ba61dd642662eeb68065a84834531833c34519cc8482b0ac8ae0a806ede5163e2730336e43a8956b289b0e72cd2f20e3677f6605ee05a9bbfccaf9424e4c571719629183f20ede8c7eba7a6011bbcba0d64df9bd11f",
         Mac => "a0eadb390b490ad39f883482995c790425dd7d01c0e1f86252527f2fa92b948e320a54900fe2b95c588d3464b6462a9b");
      Test_HMAC_SHA384
        (Key => "1b08c4bc3cb4d58339073f6575ea0eca0b1ed58eb28aabfbe4d374f43f2e62722b72bb35bd72dcb3db897e55a17638e2046a",
         Msg => "e735bacfd46777da284e5ba4aa638c08dfe8d002dc70ff5b58a1b989053954d1214f18ae47dcaf768c79d73bc76a5aef30dc40cc2d6b43f368e7835425587bcdd33f3496e01fb8dcd23ccaac94a3d4130d6a2184f7394c79ef0af95dc82cc2aa258e754f473a7c5423209cc0b815e3bb9f1bdbf0e4e304351490816e97be12ae",
         Mac => "2fc24f969c156e34093dc51a683a489a12afe0ef1837d8729a3412ac41de04940331ba226fb54e37c9425edb8fcdeb74");
      Test_HMAC_SHA384
        (Key => "40eae6b8e3abea17c069f0882649577b1952de40f47c6ac0530a036b2f1a1f714b7b2335cfbe27ff3390f9f05f47653c11bab4937e5673",
         Msg => "d2813f531ce4931cb290899579e6c75bea8a324db875b440b2463df5ecd90748191b1fa93c1d21d0806742ad638e949e1a0986e53140aa5973e6bc5b0989df0ce66729be628462a824f909dd468f987fb48c0a2fd5cd99c96e15cc4ec3a5b122ff0d6778d541e00a68efe50d68105b647ebec414eb4509f86c7c76b6605606f1",
         Mac => "3f255480d645369298f7724f42bca1b984233852777ff7f7");
      Test_HMAC_SHA384
        (Key => "4e589674030c40679c343874d6a2d6256355eb95484e4add84a087cff2c7fee7703a177e4144c941b00f5de2f602750d5e4c4c9ea7c13f",
         Msg => "e9e83561cf23ffd44a79ee7654c8f3c7802a5a358f2ffa883e69af7d632e0ab1389946c1f7d27eb0a78f1e8935db9845c61758ee4c3ef905576db9222fa22ada1fc32be513e3178066c23c11f5928f0a78019d0f1273c55b268fa5606dfed2ad456fcc154cdf310e2e173057bb7641de3df013e00857c65252d95b8045cb69f4",
         Mac => "a1227528f8c21cf04c7c9e6c020119bb6ee907a9e1107c61");
      Test_HMAC_SHA384
        (Key => "d4490fb977fb66aee9f2dc8117b4ea926e507cf34bfaff28b2f5bb2b42b663b46846eab6d4e8992d29fc5f17f92368c0f0a4f0434f0e5a",
         Msg => "3ab58484ad678e4af118384b2cef66eff7a82b09a8d232add73a5d421ba7abd715c75fbbb06a5f47a6eedaff47fa2dda767008ddf49ccceee1b238e87f7745eb3a3e4ef6e51674b7474241a1d6e98c40c20f9cc935c490f6da9bfd109c5eda4db000995dd5d39740dafbb65a612348c9e46f30f6f5b1436acadff5e4f8c531a8",
         Mac => "47ffe392039a44404bf63783b2408f85f25dda84e391483e");
      Test_HMAC_SHA384
        (Key => "dbe1056299fded39ae361a693b75e1c35fb563b4626562c8330e546d1536b6fa9584a3efbf25a57e916dcb4bb0c2fc715ab68ac59c730a",
         Msg => "522315422009b6a85766d1f9b694ac7a3f160cea83ce9a5a1f708b3f873780c602d7ab67f6b234bd664edb95b907de45bd011d3feb617ce5edbd899f5dd05f2bd073ca3513c9ab28b4b99e43c4a1dbefdc485a505e153b1afd7f64a680c56c45c2dfb8d4feb4e390498d632c60ca6a21a4d40b4663529ea059a0657b777c70b9",
         Mac => "087167ec881de09e711e3ef401bb3fbe40fda71790f74c06");
      Test_HMAC_SHA384
        (Key => "05233efb47ca387cb8d82c87223c5a2dde3c0181461775586ce9724c0dceb007c04ab7be73e9f5fb18220ea09c817329190636314cc81d",
         Msg => "6bfdc8539fe6bf99892c1c36d521f7b17c224ee3837755fee57a0dcecefb183e09e4cc1dbc19862253a2412eba0c67d2cf0ce61117668767af0d7c0a868c376fcaa48310a037cd6d1865c25060f4205638f5c5aba5a40d15ea915a34b4fdf408958714b3b3083b80c2bbc8252fa1ca459e23133997fa8e107c4cd2d4bf17f60f",
         Mac => "615219d2c623d5f0b4cbb5643bbe62d9027c7e6436060f8b");
      Test_HMAC_SHA384
        (Key => "beeba7959995358a1c238dc2f457f3c0aa6f47372f5f3471b85fabf1cba590589a74b385915501002ba5fc99094f684c45db476804a808",
         Msg => "b22d8517c117ca7f2558ff3733c23f42fafd1d30d1d0dd8a339ce570cd296e81d4a57ffb9cea1c236700bbe87be3f7c3778688e1e617738415857ea72240e7e15640558bb4480f25d26c6cf6e8d18bf327b443e24cad5dbf7435015f32676f53df03f00f31b80b4c0fa3fbaaa413619ab38f377b2a1a0503f9b557e124266ea0",
         Mac => "f1afa54e4a98b1ae4cc1cdee67e42386a36d7c876c677384");
      Test_HMAC_SHA384
        (Key => "2792a9ced0630f51705317f4920dcd68b367bed3fa4552ce23ba5cafbd71f00e954c7582724afaac02aece77155e4a9d0989f26e858cbd",
         Msg => "13adde3b88ea960a7740685976c0ae6fbd9286417df2c89573793b67bc9e088ceb7c6e9559d6b8f6bc586c68fb1fc68b417c64d051f54396198dea938946e576a5e375cad9f2861e8d0ae163fa52a3953c42ee9ea8aede775f00bf9023c57d726a6b5ba3b148e8c913df30131a5f2fd5d56d8b722b23827f6e5920253423b6c7",
         Mac => "49bb81a087bb434af90af426bad3e1ddfd83785f415d0633");
      Test_HMAC_SHA384
        (Key => "01455f93e0e8f592e423b53e57a4e4db40e85cece4ae2e4a8eab8b748c7fe5267ae8512dc335307964fe0e74f313ca92e0b2f729fcfd83",
         Msg => "9626bae98c3fc215767776230ac0cfbba413b7a730bc12cf4af8ff67a4c15b67a8e9883b5f666cbc92edbc602fc27aadedcebcf433f2b03b379bdd7b6396ab0cfc26265d0554ffe86187d3653954b03e9d97d6446ec3baa07b76510cea518a43da061db546b283802c6e459cef207a55fb988bffa7d83ae55fb2e382029901f4",
         Mac => "3604cd38ecc643116b67e173e927af54b3882d1acbed1fa7");
      Test_HMAC_SHA384
        (Key => "7cf34519715f64da17f163fb9bf0028cdd8f34067fb7d1313d078b447c1a234e2508ddd6b32f31be8b33c36e8c43952ee89e7bd23256d0",
         Msg => "fa4240b15010ab3b94dcbce24fdc69163fa57ec5ab378f7ff33a31d96b876a0f69ea65ed9d266aefa13a0ea7d1e3a75f5d6203009d7f5a32a4ce80c517315f50409ea5175e23ba323f27f5ec11f20f6a7670d88dd6312818f9b51916d5e77376a4e768f93a0c824e962ad97bb710897eb1556334ff55e37b1b7662934cb08dcb",
         Mac => "a62d888a3b94108f7094a64d8b7ef34581689f50aae08d63");
      Test_HMAC_SHA384
        (Key => "2afe865562bd56043eb122e604588301357f1f35bfab7bc274b8110bbbc0a39a863ece638473e24d9709f1ee88f72696faa458909c4fdf",
         Msg => "77e654866c79866f7841a2fe60071e62ed77c5cbda76b767f1b6b19070878e44b1f00ed50afed7e1f35cb985662436ce8cf54270954647bbe7f96cca7c3317fe856cb0ab54c2a9107893bb8d2a4a7210e879ebd15f29dd3f8e6ed639293ec7823b82c36f106e04e3520e2f7d7222d810492c495400c77fdb2d3a76463e4da7b8",
         Mac => "39183d83b1b1cdd5ef1bfbc118eb9280c89d56b4a2929976");
      Test_HMAC_SHA384
        (Key => "c13b8fb78341d426c2248f091b597123d263ffafc7f82da5a55f2f395d1c8ca4d3cf7428d65a534e5642a673d1580e820f98a2030f518a",
         Msg => "4fc6b2e78759822123ecd63ec36c773494221c2e2335df337370ee024d468341d71316d768a5d1979bfb441ea24c5afedd4c8b1cabaa545681dde46939201912acbbaa748285a6ba49a71dfdc5a21c688794df9ac1b7434b592a7a333cf40227f546d8867e00e9d35677c9a3d375a7baba8281710d62945b24df1727ffc928c8",
         Mac => "5c4311312a0a6a1882ce939c8ee4285f10ac6acf61eafcc4");
      Test_HMAC_SHA384
        (Key => "23ebfa07e8183a33de0742decda84f27e7bb3266b6f1ea6c524f780cd7d4efda165bcb328bc3837c904c62afcf449214fde47a4dc6754a",
         Msg => "c30907938846e570cb36346b5f2791ffe708c61aa4e340c78ba8c40a9b2c5d0b6d7199770d28f424087495f4c6f138fb1af56ce41816fe9027ecb50157183f77f4846cd85bed9a550c9f714b0180d0673e50060eaa2f46fc1d60552bba4c86f67fcae87e1a9dbe4dfe3e2f39b7dd3f8b7aa2fe610138ff51968c0c4f6dd218d1",
         Mac => "0cfc3607b4e9bc8bf78a81fb78b1448d373bd7c198e5eff9");
      Test_HMAC_SHA384
        (Key => "72e3f7b20f0001b2f6d621ac38be9ddfe812b49fdae482a8abf023b201d01b45146ff5cf6ec02bf4efb0462513594674787844a69a2156",
         Msg => "5e9c92ce2d88ff343cdacdc0f1ef30eab51e79d3f7a637d573e4a35fb4ca3b00d78cacc1939cf5b876d9cada710436119773858f22096161b7653b47eb5aedc3059f9d7005c8e495e6752ffa21ca66fa721fccdadef82759f53720885590ecdc6f3e2c828ef412f21517c6c7072a08cecd8a165d345bd0e6b6c21acbfa548274",
         Mac => "0db147ee434fcd355c5c41cefa376ff135074c624d19e228");
      Test_HMAC_SHA384
        (Key => "820037b251f283a52f6c19177dda02fe2416060fd593158e96dbe6647a3bde72afbc3325be56514a0f617d24ac4cb8bc4691e6797de82f",
         Msg => "8746453e63f5acf4c8794ad8219c971442f599260601ab8e36767dc9add35c83ba3cb309c685d2fd378def4d94cd6a65e93056a46d25340d62f301403d4e74a8072781f503c821cd911f55be525a68788db57539d1902a88dcc5cb26bc387a4234b0b5ec61e520cc9dda8514a46c19b3f62b01cc7c6a14666d92e36573bcf6b9",
         Mac => "77fce55d8e0f5ebf731da846b4b4ea50c0e35d8bca153e61");
      Test_HMAC_SHA384
        (Key => "a8e05f9a3532bbd1ef24c93d235ce5dfa2f806dcc47fe61bad17640ecff926d0b0238271ee4c9f8e801dd7243e9e60a5a4ef2c4cd3380d",
         Msg => "ca51c4875c2fb06de814abc6440dd8325de32fe07c4ddb5dc865e0a90d590190bb63e13732fb68f63c4b6865dbe381ba46ae42522e24908d45c24cdf01b730249de1fa3462f7cdb82408d43c0f242885a459f424fee1d74b5a9989e0d6b5c2d079b257a6748da65ca73335706738963b7fcb8e7f74ea763f0ed2e0d313ba7e3b",
         Mac => "5507bbe3f44c28bda055fd996d45af1284c26a8d39ff1909");
      Test_HMAC_SHA384
        (Key => "8860418e48ec77a2292c518762076b7a0cc6392ce1c9ee1743789c11807d9d2254313393af536b47b900474f13df1bb8609d38a70599c8",
         Msg => "107fd2e4bd7a19a4ff6f482d62896da583c3277e23ab5e537a653112cdf2306043b3cc39f5280bd744fe81d66f497b95650e7ddfd704efcb929b13e00c3e3a7d3cd53878af8f1506d9de05dba9c39a92604b394ea25acba2cda7b4ae8b08098ba3f0fdea15359df76517be84377f33631c844313ac335aa0d590fec472d80552",
         Mac => "512805c9806a4739d04c194a1f1be679e9e50e313fe63ec5d12cfc3cf4b07073");
      Test_HMAC_SHA384
        (Key => "f15776976b372abe66379961f0787338760a9a75ef51ec4957ad5ca95f5948526394070b9cffc12a97478359e503929a15e00089dffb7e",
         Msg => "cf857754d18e6b8b32941d69fe4416a128910b6820fc0ddaa7130099e3384eb7aea4ddd634ac3e8dbd42270ec7be230658df88c5920ca99f88e04e9250e661295aa1ea9fffd03e485def722d630116f6288d200e81e72701d2b0d22924a08f89788388f95b82d384bba4e80ef99559393fa5bd8a1413edc82e8c74a587ef40a1",
         Mac => "6b442d4f5cd3e4bc609bd2096db31f2b2e1e413aabd5db0aefdc599813f6dd1b");
      Test_HMAC_SHA384
        (Key => "6fa08ac6d358f801de4e18dbdee3d860421d336a0a4e4b697cf0b96019d42130cf7c091970c5eb7e63c888e89a03804ec3b42094c3867b",
         Msg => "5659b56248400d7cdf101c0e2a6e887b10748f58e3fa3dce3914e340f7dbc62eae71145a2b3f1c294981bd4b0a051f9ee62fa25063411445e6d927b8c9bc2224add1d6651271d41a25dedd4fd8109a5938b88d00fc7f48e4598edd191e549515fc83e5cc255c9d191a2d6360bd186072ae1539b0d43a41743a3bedac1d2d88c8",
         Mac => "6454d29d2082a32897d3d783259033c1e877ef9060d4a5ca8cb67e3cff73f461");
      Test_HMAC_SHA384
        (Key => "c696b906b1edae7f82050db23c1f1f9293744fb35cd53b0c438f07fbbc91f6893cd13bf0a8eb0c5a0e0bf9ec930e7c03ace4d1bd913907",
         Msg => "283a9d5d58e33def86ee9e87d20d7e769d2ae928ed44b99d137a5e1d8c65db2826ab11ad63d1407c2251cbfc7ced3b21ed428799b4a093467c19f6f13bd8003d5bb5fcd91806b2fa29b73009a29dca981907609b0796dfd5724f0a90c9ef7b91107ee44b3c279b53e14756140ac433c468a0fb97b0cea7323e442362fe51530e",
         Mac => "d5515f18cb9fa799f1064f7a242e53052b6a0917d528b40d4e87ad95822fce33");
      Test_HMAC_SHA384
        (Key => "68ba6148eb2c56c1b764272b236496d19bfeff2efea5dd60457d8fd966b45d587715b61717dabb460ac202b9236493de67c337f16f22f3",
         Msg => "da1fd0acfd4ad64d4539fb4a4c69d7ab8cbfd206d2253946f07492abb2962d1214ecfc77b2eda4b88010d49bbbecd613209e64bf5b6cbcb4c2a8f77c43d6965e9b115ee0c9aa668bc3136eee67fb72e6b4bb7f1c3af1c6cecf6aefd38446afd9d8569df22bc9414f75086e4a37ded2aab2dccc2358fc7d1d808422b75d2da10a",
         Mac => "21f753f59e3a635536f4077dc15ce736e6490cecdefd56bcde91447f03e62c14");
      Test_HMAC_SHA384
        (Key => "882c0422041c466469ad9c8bbe94749a059ef869cbf43d03fe9dbe4cff440ae7f83cb95670c1a4631c8156bff85bbdea97662552b73568",
         Msg => "33cd61eb27d7ce4389b95180bf8fa4476ac88b1a9888acd83c4aa183dbca4c4687226ab711336b597b468265acf3f8ca6743c5727e1161c743b6d87640e51d7228d3a03d0d9b2263d2e2c847e4b66f2125bc4048298b84ada553b9a824c2e5f8fc282a0581d99b6778d34eaccfa0b2568b7e232401bebc93496a6da3f02a4dde",
         Mac => "204f1ca2db1afa72419fa024c757bca17505002b80b55e86c01cae05fee6a26d");
      Test_HMAC_SHA384
        (Key => "86fb0597fee58d6f6df38f27479c319f004ec141696ba4293c929088f51ffc4ae4f5d4f6817b70d6ffe4c75924b4e0b5577f8ad0fbf44d",
         Msg => "69e7b951931a4f41ecd9f8d9a857a5966392f2f5b49159d806eaa52ca388a9c912ab3199a33039fd48135d6ca632915e6c541268e4699da8c814de6356662beda6ed72c93ced7012daed24199775845035176e67b0ace1b413e06dd88ff1e8a0ceb3632985d85c48496e3628a3a9e63566e3ee3940e18fc590583ad377af49a9",
         Mac => "0befe5d0ce9d18f38b890822a8a0856d77e83e93757fa3cef1654027e371d25f");
      Test_HMAC_SHA384
        (Key => "5d20020a5dd409c7e5344065871e57e01c91a443501dc8bf619890fe231319b5480c3879dee618d319962596539e2970513fb5c0c8eac3",
         Msg => "0463fc7ec28c9f7e4c90efbe3bf36c8f2c35ab076fb2a601ffc75664b73684a9c2ccdc9754414351975f6a93e966a33944b0f401fd916a91b281b0bc7e7de0016eaa9954393c52222b96ee8f63b290023ec4b0e3131a6fa3214727fdc580477cf1465e3ed94675f7ef7da238129fdaf202ba073618165a3e3461e3b1f6085f23",
         Mac => "d70579764dc3f19717f26fa40ca089d6262198db1a1384b2380dce8a7fc926e0");
      Test_HMAC_SHA384
        (Key => "90fdd9cd8ced9b0c7a60cc2184aafab1c93a6d32f7d75c511c2a6090b97d283419c26f5ee0d72b78e70807d247d6148db4f6bbb90d9df7",
         Msg => "8e7e9bacafae86af937fe46b25b9a41a858e87900a883ccc88bfc9cdce4f2ca7730942d5d369e9d154c861e2eed3f935ea3ce730e9b077032908688004c3922cb9b4cd966ff80fe7772bd4bbd2dbc32ff33d8e3bc51f1a43f01ee0e859199324e7e602968d43411a850f039dd9ba4b3028fa445aa7bf6cb3666af8aed53975b7",
         Mac => "217d613003f59911efa218758f537633640d7e68d5c0bf0a3268bd796de728a8");
      Test_HMAC_SHA384
        (Key => "78bca5fe23d54e6509120e05cd1842d3639f1466cf26585030e5b4aefe0404fe900afc31e1980f0193579085342f1803c1ba270568f80e",
         Msg => "3a9f2fb04c0c42b2dce178313786aa7713256c96c90ce2f2be53d5ff22bf054cdee7c1c1c795b625186f05e21fd7980d360fb5a1f5a1d30ba6feadecf965961afa060ce83f688fa76608b46cbf4375144575cb86d3637f3894d63cf5bc89eadd754537ad1c4b7640aef2ad567d91e995289fd5cdc9198b807024aaa2d1f4a99d",
         Mac => "d03792fa24355abacc837376d23bb6ed504a87018aced2efa5c97478dd321523");
      Test_HMAC_SHA384
        (Key => "d2f055e03e94f39e7bbd1d7a1790e8820017cf9997fd616206923660d315275bb633be05a8cbecdd3df4fa543341c22e4b441f2c5750a2",
         Msg => "d5f3fd629cdeb3144002593009941cb83cd312fb42997ec406304fd19f66e9862fe428e30bbba2b41c402d07851aa2e38599e0379f4a1311f9c8361003d4d61c58a81954e9890048589ce969a2fa58be0106f6d811ffda0731d108ce2c31379519e8d89e7f6f533abdbd943da95dc6af78c35ec4dee05c0e75f4cdf263a49559",
         Mac => "f4d1a62fbc71184d3ccf6fa3255346d005269d0e5ed9d8655e1013d9a5a9ada6");
      Test_HMAC_SHA384
        (Key => "3e7c15fe168a67d56f21f95f513e9fb1ccb9a57926d51133391629a016523574ee0b864f33fcb7effaf233a4a4ddf704bd279adf24448a",
         Msg => "6725cf53ae93f5cdba4b7f5bcf0a84c274cf591931906d20982b70d3829fbb3f9b7cec952198d07de80487aca23ee2b95da8102c4d397ad9cc73eb6c9f95f4447b118f85c7400268a45506d62b902936f5b47183e1ba42a111c781f1365cfa230eccff4b2bf45237f5264600f26620e045d9c343757a8d21700f7c8ad05c9583",
         Mac => "6f4001a6fb68457ef43a140b5da5db50ba88de93ff2326d25eb92c69f9919761");
      Test_HMAC_SHA384
        (Key => "b8dfbcdc41f1b7994868eb6cbb8a58ec28baa6ad2449aeb5ed8e3c2f4e391364c3e432e6deeb560ee97ec0a9cdf438ef336252b5e86df0",
         Msg => "14c5e750576ce3cbdc3d8db3ae68655b6674eb149fdeb1f3a903b4d5823feca1015722cd55140224ae3171c63a782170532762fdf7983b2d7821b9a6743a873808ddbf6541330021d36cc1d60eeee4ab0db38e0631ec374fceebfdf8233f3eba90216521030f044ab4b624ec1215d995fce019363522cde2122729d3769939ae",
         Mac => "1786bedfdb204f5a4e947cf3980348410b97fa162d89e73a254e3b2911420ec0");
      Test_HMAC_SHA384
        (Key => "ece8f08f7a942395d29452ba8b298a6ab736f6b17e4fa6f305128fdd95bad39bf9f1434b27e622b223a02c2e2192d7ecea6fd95b803fea",
         Msg => "2b5c2e7c754f246b7045c43e191d075c54f910a77f8a60ec4d8e4d7dd296b01cda0ddf1b7f76dbc2fbf5caf1ba11a706b4b83801f98340e78d3cf764779eb7b3155bf8c3b2647e925a64d1dded8deefc73983c08af07c13ef7ae96a8437198fa834f61ba36a077a3389ac24cdb1a44053aa20401ca9d4bbb32eb13925d99bdb6",
         Mac => "11ba8965cfca0d25739c97793afc961cdef0735c021344621ea40adad58ad000");
      Test_HMAC_SHA384
        (Key => "3abf1268a892877f4267594f3e72814073f8bc67b35683aa5c453e252a5cb5cd4fd7c753c6965e4ce469a28e308a6ddd746bffc714b2f4",
         Msg => "8eda4f99accbd728c95ea46d31bc0bfb82193ccf128bc7ca8b1c5f65d81edda045be883be1dc9329271ae742de3323383e8fe1cc54143c41a83e8f111c727ee0178f3baee3c7025054ade621ab8ed0f5b905c54e48ca67d3b6cbbffde37e39144e75f05a7a332c86973e29735e751b1a3da46ebeb4565266ffea7790f5e91524",
         Mac => "c6e34c6379ad0db133962de9d7712bf2bca37fd2221d3e10ca095f1bd24ee412");
      Test_HMAC_SHA384
        (Key => "304f1de5e8fcd7aee34d5fe5127fcfca0bdd112bb0d9a41f0b5b9cf77d59eb7218a8e0304912ed69baa8addf765925114fc44bb27d4bc4",
         Msg => "0b995eb3f8d1fb4c1be0a7fb364e5d1b4edf5e3eba5ddd147b97fc8ecbaaf742f87f9f1273950b0824018a8501b3db9bdffaa1b7884b11830d3eee0a5ed9b71e17111ff69d8ebd1c6aaf0587a5ce7703f6c516da98b01cadb0f5eca3dd8248c61056c4a99e437a4e93f200484a27971d3a46a5ee1317665a0ac6de9f702e1202",
         Mac => "03fc9fc8d4f186e8718475c6a3e8238916efa828b54042932e872bff0a1362a6750563797d3571e8");
      Test_HMAC_SHA384
        (Key => "9e1c51d35e3636ceaec44d7ff427ca5e98b3fb8c0ca77364096367521bd558e85f35f22e8bf2353a30ecd2013ce3d86dc32f8fb0ffb2a4",
         Msg => "d77721f0ca5a83eea7821073d40990fb6cf00b36f006270b390bb1deb116790ec33463c29052bbe6e45dc97068a7a5e8198d4d27f857f55f035f9e5b6576ea08ea832f35b56dca97353bb610557a5d30f3dfadfd942e6fef565ad43f26ee516232abadd0a17359098266ffda034a5ddce430543f2b543cc518467b115b475622",
         Mac => "6321b02d91591009913f8170fb0b5ea6793ee8bb32a3e62fbe11cbee2d067dbae2611420a03fb003");
      Test_HMAC_SHA384
        (Key => "53a933e5113a62ea85908a388ce7858cfe850e09834130daa946fe18341585eeb6c9fffb5f9f4af715b5989ac71267b9ffe7b4b3b7146b",
         Msg => "6c37a65405b58eb6d79a0fe5777687975058dcec98ee10ac82ed15d0b5b3e345fe2cc9ec41f200e5b6b8860d51e829c5828be2f61f6a65529f72f6dc885d7eaa2a8fdee98e3e8323aad63bbdd69c47c48491b1e92b99e0c984dc6972f96d28235b2a9054d3e33ff61bbed5fcedd9071abc32efcda3c4a69b9bf3159cf02a0839",
         Mac => "dd1f092022bdb437755b8900df5d6990c5ddac34ded45d8bbb8a794c928a16feabd0058fca2ce160");
      Test_HMAC_SHA384
        (Key => "c5f1b9ab6535bc70ee5473555fe070b67533fdc3711803d31bc72afc071742e017efe2c941fd4ef992ab9e3b734f1dbe2ca2f023a674f8",
         Msg => "25c2449f1885615129179a20929b0ff99812508160ddceb4037c8fcce49c26654251e3de09a04702ee40bae8baa18017e62eeaee69d0c944ceb3284b894c3bba8b9b922b14ad92c1c966260f067db23575c8494ce0ba1f05432a418c265583b32927ba4ce1b62cd6e210455d1d368c9b6d68d5636ca3b7408b69405962c0e897",
         Mac => "6714fbc0b70c6b0ffb33a80aed3e511762e87c5c9a1bed95b67d03b948b215116a11b94729a38ca6");
      Test_HMAC_SHA384
        (Key => "8a735e5b19f0aa6c449588ae2c10bb645bd4bcb5a76dbba55910e0448f77d625dfec8a123da330fe1f4c883bdfe95fee60dd58bff446ec",
         Msg => "980a7fb38f023ebed635d2bbf5d82c2881fbaa38f10e8e78ada3afb268766e11b0aaec87c3557a6ca53f51686fe78492eac732d95cd900a4a25ac6b57fce89533444aaa851db5c68ca855bb34d0bdc3dd352bfac76dc0c4182919dbbcec018784d6121dee09dcdf96e905965374d1c6f6522ba77e41e9b9974d19b8cfd5303c9",
         Mac => "29e7c7ae061a50c471d5e7fe3faacb772d5fe1fbdc072e76bc4430307cb0f68bf8b064c1ff2a859a");
      Test_HMAC_SHA384
        (Key => "fc63d7b0f56a3290c3f3f75f3f09579bbb45d6c48842f46ebc500d96316d7e32d171090b11887bcfbce58b62f2b506767052295b12ba4e",
         Msg => "36aa473316a8b206a22edc8e33457d39ccee612e45b7b186a98b74b9dcce555681aaa7f81aa3a6757172005838109492ec11796cff3342c0353780694fef89f8e79978a89b6b75956d6f37286a91c6d68af7860ad890715fd2f0a413135b1db92f1fc32ddf27a6cd5ece89e612f19e6d6f4890f019f6c6cb485ee79f71399900",
         Mac => "48a484bf9b7197a56f34b2318fe88a8f133a6553073c055b6410907316be7a08c9eaf2dbb4791978");
      Test_HMAC_SHA384
        (Key => "65de751a9abf91c5de639338618e3df81e9994cd5517ef7d3cb84fdbf26dee00b4cc1bd953b744e2e5385530bbb041b59431ddc01028f5",
         Msg => "7197b130fcaf82b3d15a47555ca3ef1338080e09a324e8352f8bcb7ebbf6a3f5a2a0c85a32ef1ae260575037b97c8dc19c963424a71afe0a6f974a2274ddb4695465e8a83eedb93daa636d1f47045b1d35c5b96675f2af4e9e15af4fd119094eeeafba2008f1854d17454614ed8582af6c5d42d8f5f4228b23cea50ebaf1cb2f",
         Mac => "167601cab956a83d1013e78cae3ea29deb167b921b0b8627934814e9e60566d3cf42766e3a00ef7a");
      Test_HMAC_SHA384
        (Key => "6e375ba22837129d1af55e6306bab99cc29346e83b49fd76ba9309d3668b6eff0b5fefc619492f4df0c116ec5af1763b5969ef70241410",
         Msg => "a8fc55fddddf63e81780d2ea6fa51e14fb1bb0c7f24d17dc111595233dd1dd0f69ba1bafba7135e0e9db50c2ea2f9768cb4d37d4de52ae221a694603bfe4dc6d398be6914733b50e5c93f76446547fab0d6749851e9bb851a86f23a1472490eee017bf8bcc4e6bd83851ccb8cb3b60458a10ebc2f951bdd083ce33e51cbc80fb",
         Mac => "fe9ea791bdb8326a8fad6ebdfa160fe129b36beb7c3f74b8d9cbe43e6e61e7592827a5f16b18d1f2");
      Test_HMAC_SHA384
        (Key => "8968d657a6b3521038067b70c3aa05b2a3555dd7e7ad27486308ebbe01760b5f5801f92a8033a69424d93e73d807121cad5cd6c803870c",
         Msg => "1c78cd8373d9b3f3fee9b4a11c574d6b429aad0e4aedb2470d9813393372df0f4aa426e216aff5dd28b1889fb2e4bce09a67c358cd411bdcd6a3c1cbaf6da2a8d7f45208a40200afdb1faaf67e0f8d70e59ce0cc1096c1fd3c177099b40bbb7feaf0b9bdc6dbbbb13ebc806e27e2a8604bc26b34bbf48bf2677e876ceb5512dc",
         Mac => "f1c322457c2229250661c76555c81c3e8a2fcbfbf37c89ac43940a47a9513437081936c03fd5987d");
      Test_HMAC_SHA384
        (Key => "a16a45c20c1b98dbd2dc638fb7684690f626db9f9bfe3cff2e6cc62a91d21dc42b1370cd475dff1ab646da06bc1beb652a7436b9c70c60",
         Msg => "c05e649d3fe1142330ca683ede042dd4a64ac41609e9d461ffc73c628da44c7e99a03471fefdbc35dc27362531f1b162ae227076c3309b37fd4b33ee919d4bb939d1762e3ed27c41d6d55168b19947fdcfed82e39474ac6c1ea5eb7ad61510e545f9121d2ae6ba11c9dc9f4f8583556cb1b4e2a6a43b71c80bdc4b4e849402ca",
         Mac => "484c5d6cad99563ed7ff8b2b6c1d59056400bb6d29572365fefe82b55b93a3db6958e5893723284c");
      Test_HMAC_SHA384
        (Key => "ee59b47d837ce466a5c6361ac4f64365ce5007de53372d17e8fe8d16c9fcf409c2de23354f411a300281965025cbd863a17aa8a01ea09a",
         Msg => "7458a8f4cbc15e390633de7d2b2df46d06dc6cb26d497bc3c8d25afdd0d734f596b5420dc7f835452fccd4547db5e6f84680528a4c7a85d5ffdf14284495a2aa761a05eeaabca4c73808235e77844381c7a1033ed5eb0cb11a834b1aa5cfe0321b7037c0fc74746727cd15c2a102d2b39225c8f79005d7fe20a449fa7aecb437",
         Mac => "2a18d6e05b4e386716fc5e8b5395c79d04ab1786ffede68ca46d4c1dd7465c6c1b2731c4a1d8de60");
      Test_HMAC_SHA384
        (Key => "6aa20e80402d8de895c1524f7aff11ea645805588014e1cc46990a6d51ea03fd6e6e28b9f3f3a08152f28d39ed14856f2cf6463ecd29a5",
         Msg => "c9947b1f99a8f4d742766ff968a250653b2ee24af8eff93eb23dd68e52ef4ad2dd871fc5f5a9b354a3d2e6f55346363a204a29a65294ecbf25003964cd847d61b6663b4110acab648bd5a8515fc6c94c9007cd2c702f3c67659d4b6fec690041de9a983af39a262d84e77cb4950a4ec312cd958359a9325df97ed454b9871b99",
         Mac => "e568392f545994c2ae2c845cc366ae8949b73d4c46485412f63be61e315ca777d909b2e841f65c93");
      Test_HMAC_SHA384
        (Key => "dafff4db046073b89d3d2311939d7fc9472b1683e33a80c1ee06964d1e3ce3d96dbd55e26e9f38dae275658587d1b7a43007bfd11a33b9",
         Msg => "5da17f172c06192b866ebbf35f8e97ec0ff25a1c52ee54a593d6d99a6a71e71163ac087a018c7a2f02668e4ce5524ec0aadd62a4d9fe35ccc54c539c126d161d75d28150bba16cc30df3e1617240c78e9517bd74c91349974a0a32b0c5872ab81b7bb043632f350f2e7d7edd0e40497f590933332a14d92fa97a3e7d8ca76d09",
         Mac => "cb113d1aba8a763b774833c24f200bf28facdf7d75506cf3c9a16b14937a307eedf32fc640382099");
      Test_HMAC_SHA384
        (Key => "ef71b7b3ca0f904dc50447ae548096b2b3603b312a5e59d490851b270ee99aef259401bdf2c3efc3b1531ce78176401666aa30db94ec4a",
         Msg => "b7216e9ad1289c89d8d590f9dd0487c897a28a6606c0388955e5c62205a9448f487f2212abd3f282f8556f405b94bf6dc3cef55a8b06da405a58ed32488aa84f42e3053caf4041d25364e0137490f1633c5393f55fa4b883fe2e2942caebcb156cf42000259810e0b1abea5a7220a612cadb6d1dc9c05bb80810833ad4f53347",
         Mac => "13194167194dbc07f67581776840ccf1a160c5c465313f53e013daba7d405880ecd7124295e775c5");
      Test_HMAC_SHA384
        (Key => "2bfa932702a35ad436912ace48999d18c06caa9e680476beb9426d0793d59241315d13ad5bd0218edd1dfee7391058879976d5430781ef",
         Msg => "e8cd40f84cc8155ea751f0ab617d9f48d1984e7cb0c69f33ceeafdfe03c72d5a69662535c8b722ae527af51d91609d539d6e1b2392a3822141da4ea926f2f6239b2bc5864ad3e51be823bd8421647dfcce55f6e06ed1b06fd4ad36ce1de0b54ee5e6c5f2bb66872cd112f0e8f8ce64cbcc1587bd2c9950a5ee2a5f73d0d99064",
         Mac => "2d44160a46ebeeef54c3f84cb644224279635fd8997ae5692b4710de8d7d8210e1aea092e62f2893");
      Test_HMAC_SHA384
        (Key => "bfe6bb4c9b171b93d28e9f8f86b88dbe509c66eed41818a1986d75b616fee4460f5456cd23667c8a9f1738289601519d33716a534db235",
         Msg => "5b7a078f980bb8919743bbce52fd0ba3c22083d2b0254e28c8d3a05def4da33bd64fb502cfb5d00ce03d49ad168dbe5d1c784a190c7dfa0685908558fe1e37725a4b2f4ebc7eca209c1f5f361b9f2d2393b9911c73f87da24a7a256221f3fb590ef4de3b066e8e16f3726432063a403d4f6dc2a48b9fbd443d17e84200d6d737",
         Mac => "e82eeb7f4b7415a4c95dc82c46bb59715fda4e0bdaf64a7fb3af3c7058ec7d2a172b8293057b72f9664454e7dee11d95");
      Test_HMAC_SHA384
        (Key => "4cf54eb8cf7bd421ddb0586ac4fab9c478cdaedd89cc5a195332211f7571b9988419843300fa1ded868d318f48909078bbf1839c8fed61",
         Msg => "d22f194a1af33cd8cdffe9967f677acb68500d6cbbf77a3f34f58840f0c16044827641dc43d6767ce98f85dd5cbeaa9fc5b28333e7f20df8b281cfa4156055e61555e04a1ceb5c5c93ba9210b2e89f6197f0a53996a2c091d16c3cd908d7059ab2545e5a4c39d6c0f10778f82bee43590993da4571107c51b83c35a6702e56a8",
         Mac => "830b4a798f85c448b3d54abfee61b376597f65666d83a21052cb3f4466f44747431607bc659c91cb520308fbf4fcdb58");
      Test_HMAC_SHA384
        (Key => "de281ac95941750111396ad0e152be30ebf8c47c2dfe8bd5562b56c5d7f54c223c8c7135bd1ad51c10490c6d8207dd1c46863e9f0d8681",
         Msg => "ee6922e96d48b6e0b52a1cc6f3ddfc7b1cd11786237a1fa36ff6cc7b8cf02cb221c43b2622e3b376467a25c2bc4e49b21aea93ba96fd069c78fe4d2ecf11085d632e6472ec80ee94810ba98e53925dd39bb833bfd1657f201f6bddf5156a7f769ef1c55433e50e414e27cfb32271e2e58981201f3e7a31384c87a359c6c13a03",
         Mac => "a136b0ce4e8239ae848c5dd84a708027b0083efbb61589b2c30764def27e2e1b221ffb4d18af81f27c35dccf0683bbeb");
      Test_HMAC_SHA384
        (Key => "790bd8d4e9ff691a6bb8c0cd64d68d31195961e2c46363b9e63f44f3dea37590bb3297fa4f4533e784ebab80f42f70c3b39976266ff7e5",
         Msg => "4d53f5dfe10ca3880f44fbc2d9bf3d1f97479f4f49ac3f432c085d918b47c71bd8e794ecfbfd1562ea7909927aaa10e87505630eec22c10fce07adbdbaa9d65012b0d74f517b20b49e64344ba145165b953bfd889ea94ff85d80cdb5c2be0b52223524d28a8eabc5528de5b4f59735bf2071d785084ad14401fc27414d8f4f6b",
         Mac => "856c255d058752cfde3e74df1c4a34986e6f7ad5a34a06c157f59d8d6b2039918c4201dd8b2d58617911555802d7c799");
      Test_HMAC_SHA384
        (Key => "15e3ca0e8d9f69f7bc8f63f05b57586c1cb59eb33ac37d3f54769f667b6bc23a8ae3b0aeb50c71fa6582bf404415ba6f93cddd68c42b31",
         Msg => "929172a72b23de3936037ed526238ba70aa8a695c04cb4c56500ec5f0fd52e94bf1c97df91cc528a3625b175a4937c130cd589b50d5e8c0b27fc31e772b7684590fc0089e0fb7807f44d12c846da288b26fac30bf7da6a809b2238682cd43287ed77d72d8076f8b759c3c95872bf391a405e7f1fe786f52daab92a6aa5f43263",
         Mac => "8d6895c2b80f3ff362dfe355252578dfa31596c8f8b028ee9cd1a689807b6207a216e3516f3d782234d65eb1f9597f68");
      Test_HMAC_SHA384
        (Key => "dfd7e7fa6dc49cac285dac27f0968e1a8bacdaceea5cabffad5247ebe9e402a828005fbab16379e50a0ca140bcf1498b56f021c2b4087f",
         Msg => "004c38356decec9ee5ac710126e804b8f6d947eaad0ce6a4f5137b2cce7aaf92d5fda287c5f78e723e1ea7c1c56e457d0d634422746babadd19b8df66da12d404ffa650fbd65493aff970740663012df8dee7fe3df20af3d595e2e549178dba0f8ac49745c1c661bb17f5a271016b20600e1bed6f514377a16c525ee43e700d7",
         Mac => "fd24205b960f569042ec8db3c4e442eaa4eb38272aa36f40327ac9f5e3753d3ee8eeefa28ec5fb1e4e1c8815416515d9");
      Test_HMAC_SHA384
        (Key => "8c354e398566a4b9bbe215f1ad7b40d70e698710753365fe56d301fa311503de0940a6c718f80e19c163ddc3c68b01c4bb03cfeebbce56",
         Msg => "a116269f6dc522d0abd6cd740c0879e7902b4a0b9bdfea334b9e7f3f09fdda085e2ef1fe08ca900f4ecd4bcb90e3b7c622e2da3e5b97dffee8c50e82666bfc5c3146ffd77697e5d99026e60e9187d6421e9ca00f815befb9f9d12e565467b332c0653771dfb48af619e88484367e3f232c6183c635b3822a25cbc601fb7a6750",
         Mac => "36768ec85d992222b67619454918b6ad9369bd002d5a1d08079dbefd35c3ae6d28f0475747afad3c3c64981b20e7b665");
      Test_HMAC_SHA384
        (Key => "1fd04f50423cccd5f884f5954c19c8a4c6efbbb0342ea24da92bd28ac79687c83af583cc8550f812012ea86422c14bacfd5e3107073028",
         Msg => "c050ea6c6b8bc0971c1c64e8b8df91397ab8f0a1f2823c004d48a4d8d6b8705fbdd4e8d217eb710b27c8fa56dc2996819a736a323ea3ca7d5c889fb6ca300c8463a0513705c7ef5cdcb50d8ee3091a8fa7a8b4974fb5c8ebd9bdfbb2a6314904391aec453c0880b1c34b6437d566638b29c194772d9e7e724c4e807371a57107",
         Mac => "7bfaebd1b8b1950274b815c26d4b7d11bfebf2fc1e0bfe4ef0a3e36196ebb64dbea0e2aa0f342c4fa021f82faeca66ef");
      Test_HMAC_SHA384
        (Key => "5a63fe74efdc2a71b87ba0557452386fc3d0bb31dd9e3a3684c8a584371d990ea9d8787d7180bf2f030c9480df4b9f4908831ba7b8592d",
         Msg => "5802a9f1d0bf3b1af5aca2a16a6e3988f937b9add7f9a59e29d3e5aec6d0b0493fd0b0841dc661f86924bbd172941022cae9377c9255eabef7dc6d2efd0870c97cdf37d86712f8c45477852b39b92a33744fd91f0faa842041b3cb6d3874d79515158614390bc825bf8c49d8494650640050e7bed6613c6b0f404792ff7bad55",
         Mac => "ab9aedb3bae00ba8a335bbcd2ca1c610a5e07fb090a5b7058f11ca5c5d884601068aafc2491ffae62db3d5799f6f7997");
      Test_HMAC_SHA384
        (Key => "52b3069b60f5375f4dc447f866090a3a44c902eba0a6d66d68a9ff9c113ec5fa30806a0a44b7a5f9d61f5283c5ec6715db8a2a2fa329a1",
         Msg => "503f4f781c453afef8a77661ca7c4f0d622d1959c27c1fb1bcc5dcf4c3836e1bfb15471c92c3260d53fc458d78e1d460c008a759c2792c7d81fd9f65409981e4985546eac7414ea84bba16f5b0eab0f1a68e70e856fce979f66417f79b56de0f4f84b3ab64ca9a17086b5062199ec9083a49ddcd260c3eec4481ad717cc26de4",
         Mac => "5173199b9551905447d3e220c3301f99006c61d2013a375601fd3b162176adc4dc1ff3c345f81f5b71de718b650aa3a1");
      Test_HMAC_SHA384
        (Key => "05b2305a6264fb92280197a579b4d336395d5b51148adbfec2a3671589641b530490feae24e42ce6744a355da150c02839d87466b31118",
         Msg => "27852e97225f7966e2da1e7ec5e615853167878f32448fd964ba43ba14f7eed6a2e4a0952942e9d462f8e1dac6ab6b8df390bbe5517e16a2f548d93ac649bd16de4059fd335fe9d1769e4d793b55551e5b0a3b9a9687712d7d309d729094e392a34262b886de01c5e4746b446c0b58a02f7e0f94498728e4c41d974bb900e6b4",
         Mac => "e36f45d68614266248a91553c18818c049ec60e233cd5ba37d6cad12d9333962a5d3610f2dddd3c0343cafb82953dd9c");
      Test_HMAC_SHA384
        (Key => "185f150008c482249b50548efe89c71aeb4e0fbecf6b98c02d6b92263daead6fdabb21809bd6f2e13fd672294e3107b7fd592ea3524bc0",
         Msg => "f00f1d6331110716041ba25d28fe48b7764238f7c372993a08bbbc1cc1b6a22c9281be9d3014fb3e7fd201acf85fb4c54eb2fe61516bcf3d126662384890c1c2f2f98b913e2bf595aabb0f2f691d499e08bc35ba514a8ee470557a3d541c0c1658a00da823fefc05ccfb534f42e10c28ec8a64698cbadf1769b28c93ad018a10",
         Mac => "47c51f9c7346bd7b4ffe38b2feca74f43df543916a001c880483ceabf6452f7a3edf9d80bf321e9de27dba18537de349");
      Test_HMAC_SHA384
        (Key => "4a6e36f56637c7b8f445b4f096c544507e2fdd3dd31e823a575f9aa44848f39f844b0650f0cb7d4d192df2511c33fa35c485621bf391b8",
         Msg => "bac382a645b43242a8274704a6a2b55905a2993ee59b295e503aeb7a12ed260ecba5973242db64befcd156b10e1a42d42f5cc89a1155404bf21cf2616ea985339798bbd0472a5b2eb58d6e84475dadf4a76a3b6d19bc90d00cd4b551ee35b7214523564afcabfddafae3f743fa73df029654587fa4d8ff34c6eb9e123d98a320",
         Mac => "f194e972fde5d62f56d5fb99137e0f2f942d0b2a6a22916951ad03bfee22b58287bbce5d24700c6c395452dfddce97ea");
      Test_HMAC_SHA384
        (Key => "83fb4a69527469aee5d72be40f3c9bfcc94225c57a4bf9be76e9b029c4933260249dd76c5067ccd483d4b9b338fda00d34270963c6f35c",
         Msg => "2c97ffb7f1937176ba699943c435b3bc481fd8e34ddd75c5c07afb5ac656d8ad516fa73cf2dea3a2eea5627393a7c068ccf819bcf457bbd5e8f99a27608946567f6c1b9aa849b76894c9b24fa19b89206dbcda51a4f5d7a316a5f5030dc0e4aedd18c499bcdb9610d45df09d9718f52b53f2856b06beb177730472b675059aff",
         Mac => "bc852d73029f8c2dd6115c5949598b9ea613be7601a5a224d46ceae0bdc0ca43a8cffb86d9f322cdc09361868e2345c8");
      Test_HMAC_SHA384
        (Key => "1b0bb110ef8d7139773117d7308dac5d11ce7c756f071df11ec8ac05d9f35ab4e3cb2789ef4eee873ec5a2620799d7f01b6884dac95807",
         Msg => "21b801681f2ba3d51ca2347f4bd2a75c5319f25901626459394a397b33816c9ce472cc1eb92652e78b65b2acd01f306f0e0bb546968e225f6edee4418f67c954506e11a423f4c9e27fdd54ac1d514b0d676387482ef07bd19bcac79d68160b9b4ff3f983c35dafcedf5043059c309f3f46688fe6315218b9a8570c172657db7a",
         Mac => "3dd9d0f426054cabd0dae1337bec5682c0778679a9a3f908c66b90e1c28814bc6b9a61d710b0041a2f17d576a69dd4e4");
      Test_HMAC_SHA384
        (Key => "c63bff382de2bd2d076538ea88ff5413d11969f50a0df16db12f8405310e0761b7f720da41bbec68f8b2f5c5bf005ecf0c17612ff67efc3890d0e6117607c817a5faaa7d9025ab3570a9f614db93f1319861b88eb2c3c9facb9e0135b356c756394d876a41a7625e1751231f034175ff1eff545b6364c27a09a1bbb911846ae5",
         Msg => "992a5b8a639ae2b2f7fc9e1353a79e521cfdc98990937290bc932c7bef5edf636e751b6a6999adf92e31704c9ded6631dca9070c4c94d91fbb914108dbdd998bf2f28292d4ac7c720fabb47065f81c847febc15ddf4c5aa417b81c853846d66c8e6b390c8a1b77a6003111889311e9d46d8c9f8233041aa837d065f9f0e1bd8c",
         Mac => "448abce3c38e7f109073f1513455214d0361ca759c775452");
      Test_HMAC_SHA384
        (Key => "4359b09328ddce80ccf1d3ec5437aba6a11ae789775f04acdefcf0d8c82eca3ff5c6e96a14c321742b2641763802e04219d35a54a91015052c040902edd97ffd25f618a21f8b12cd9a69c7fa6f1876fd732346f39fb788786e6c3d1a8763d80e9c914522925a29f3e2626c603fa0f53e79b4b44da17ae66b6edf9408dff35dda",
         Msg => "a57195bff000d768e39ce6daf66e91b31a30fe94429d4c2f222576a136e67b0307d8bc3baa47a51889878f9f66e3e59f9cd6868ca87e6b89e94d8ac7a402fa0e4bd75799fffc68275345ff4f53202114c5c967b9aec1a4d7187cc8ac135905b6fad83080f70869bdc93efe93c50c8d391b7169c45b4e3f3e3819faf98bd5e322",
         Mac => "f215c988601119873340c4cff6063ff97ceacb3eedc40aef");
      Test_HMAC_SHA384
        (Key => "9f06fc05d8892b9513578385a5c0292f0b9e9ee7dd7c4d3cfdfe607b147dd8753ff1dd82051452c68dc4adb30da906cf86196db8af3881652e643fae0ed0170f6e6e45a976135e8990d6292dd4b9b144c38b98b6390caee49d53c2315b6db9c19447dd8114cd776784549ffbe03553162cbbc7e96340fc42b192940be19ce513",
         Msg => "a30c53e81e0b4d5be3a210b432e6f4394ae755297f7a45a08d3c7eba2cd39afbe47787ef23b2350d8d6391e19309b76b473e63c26e82a9fcd73ae752ecf8f78087fda96b07fd7006a2225b76fd534775f9b554f4d072950462ba0cf6c908d5c133a7a1a5f174660ecbe555bb974a0d1f0a530e08cdd3707ed3c3d5eeeb8a9c88",
         Mac => "bdd3e637be7317f62ffb955f7cc913b65507cc85d298202f");
      Test_HMAC_SHA384
        (Key => "2f4595e175c07f52d7be52a7a8191818535eb24cf01910c21553a871ef5820ab91be4e478ba263ffbf3563177078d9409c43c8bb8c8ce4c1a9e602239148ce2e6a10bcd177474102e827425df7dacd0e308507f2108565f9d2f91fcf8680e2bb6344c6c75e377f21fc9cd7c164ca5c4cb82c5538a58dfb323992e6bcf588c61b",
         Msg => "28bd1384c5786b1a689e0f305c5d3e9b754b0bb3f3b55d4faa3339f16080443d778983b0ccc4668edec3051c3309a910f71c8e46e7dce7b46d1223a00c4c6f10ffe97c831d7082de002685a966dfd77bd714deb38936176980425ba5f99661ce090385658223c7f316ec173fbf86d0c55e5a8264a26cf4572bea6966ef05235d",
         Mac => "39dd7e97281b897fb36ce83afe4c8b06417d05e10460cc88");
      Test_HMAC_SHA384
        (Key => "ab1cec025ce72c9cc162028506d527e2cd296b9480f2a65fe6adf24bf545174ae8dd471c91c90c70efdd7e4c03ebb9aee0878e74020d7979e0e6d301c4064957dbb98db488a04b63fef65f230e1845cd3d45d1361aa22057cf81ceabf5e269d9ad3a2693ec74d3be16360dd3cf65b3850eeb9ba472b88341da064a1330e26019",
         Msg => "8c581d3fba1744dde5c8da61c90899ea1e7e1bf96c604e1a213822c7e1e884891deb9060e7df02650440eeae4377b2720e13286d3f56208635f30db02616fe0eb6a5d05ac9c5a28796a18aa5fe6786061b92b69f1b6fc8b04fdab3a87f49a843810d45f509d40d8bc37115109fe0ffed6d842c55a9b42ee098767c76948a6a6f",
         Mac => "a3f6807e008f8df4f9e1c3e8f43d1403ab5f6b2c29564ee1");
      Test_HMAC_SHA384
        (Key => "38f0a1720529576df8e0bed148c3e04b79938949d2ca59bc1280171c5f8f48ad7ff600024a7bf9bf5f95e2a31788f9c5b7d2dc1deac69c476e7714840dd77902cf20325d6e73e9650abfe2221ee58b15b31a55c1d38cc36a4148c01d675b36f09037dc8b575950e75f2965564522bec4d3329c3c7764f4aef3bcc5ef5562a801",
         Msg => "5bac4be719240c6790176fcfeb919cb23af6bbb172f31104b5b46c56d458c2d613a2158b2cf199e7967219a0069497bb37bc33eae73b4e17227dee41c282648737922d82842d17d88a42a40e89a1b39ee4b15d4a24661eaf406e351d1cab4da64fe65c7529c2cc62f5eed9c37b9f3a84c93e037a335dcaf499f00893e8bac35c",
         Mac => "738747eb57bc8caa2e1b86673916d5a5b94cb87f4d3d9ded");
      Test_HMAC_SHA384
        (Key => "8424bb05a925a6b09cad2d0528ab8d15a56606f3701aec7498e6fb32dae5ebd7d09c4498659474ff8c471eee3241b6e1707f4b73061ba324052b8d59cbe673a434082f460f781ff2cf287cd4833de7d2097145127eb5cdbcf81a5f0178f1185c1a3123178f1ad212cd18edc005ea4a72d6039dd8c03192c4db7c1932c9510186",
         Msg => "e197e4a49e73596a1dc14d330f40125b73bfccc4b0e126c1e11d43327008f8f0e6d7386b011fcf9108e053f25bc258224e9ee45f37402374c66c5bdd951e212c0016ceac37942d439161769d240e80869280329825ad3b171fa002194bc3e0ead85d8eae675ad948634b9d7b91adf04fe86e9eb7a2add67093c2222cba7e9cf0",
         Mac => "6947d49bf9c309b20edbd4eeead6c8a5f78983bc1950442e");
      Test_HMAC_SHA384
        (Key => "eff520144c1a3c67a3689baee7937452ac7198f1e9ab56b1fcb89cd4ee0c608df98c3e12474663f3fd5fa9aa784c0373d6451c5eb9f73ba2477a6a347682d79886d97af8cf0df873bc66c8b7181a94d288c4e2455913f35a7cbfebb8cfc233359fc41ceb6ad7c58ee9643efd4d65ed16cad531cf52654682a371698983323c0b",
         Msg => "a00e97afbd3fa6dc67f1c132ae81270567fef4112f25440eac909b85162a85e1f6e679c92eb103ad3aa5239fb57ff0651f5380ccdd7e0c3f81dd50974c3c3135f111a24e9c6bc88733255cc2dc5f5237bf2eb8c60d93e08b41aac1b4a6249b8f19f7dae710543d91dbda37422a0996a4d0f962a8c64c081d7361b7822aca0b18",
         Mac => "fe025dcfa6604cc3e74a0f0c775926e7a16f7396f9851c55");
      Test_HMAC_SHA384
        (Key => "132681a6ca18ad6217f1282380eccf9ef901511cb6649b213e4f944bc1010b7cab07ed3c79babc58cb093ccfbb7870ef6e69c4bce89a8c9125f0ad0a65739a20c799839619c7c995ef15b493f25268797b48150461406f6b0fc95e43d9b6f6a09066a97e5348bb5fa99df735cd80a1814924abbdc65e2bf823630dc0c4d20544",
         Msg => "d714946141393b69701994acf9c2093db8736bfa20a4e3b3cf462b8e654cfda9976acc027f1db39436ebabc3a5ec00fa98890693148408f7eb3981068d238eb921a1a405d5fa7e03729f5a4f33b165aed7c374f3f5e1f42390d124d7eb9882e29e418234ead986fe4abe0b174a1a209f9caa1de269c4917ee5987cc926b6bf6d",
         Mac => "0505523b6ddbe352de5fdf9f4f9258dff68f8cd4c6825df0");
      Test_HMAC_SHA384
        (Key => "af7855435734415cb4680725471ddc0f935dee9ddceb4aba2f31fd50a27a7916dd613baad989abdfe88f4458f63df4560e01c6ce209dbebf011f04c2b31446e3e7f957afc0f21c8edabfa8538beba6126846f7310b969dc2148ad8106eef8e78d426f07b93d65b1191de7c3f8e8eb8ebaa16cbf0273eaf6e7158bf635b731c80",
         Msg => "bcc5300e069ad4f12df78c9de7c667775d9e70ed8d972ff4ec5c72b450814d810e175f0e5f7e57dd097bb7fa3b8ad8e9b8762edd3726ce2b0aba2dfdffd72b4b843e50070ea45598bbbee68a369ba684db36747a1b4ced23226b31aeb84ceab165628b62d9b3d6098ae7a1b59f9ed92e0d07c72c00af92c67c96062d4488939a",
         Mac => "39341404ab56d3424e7a8cc4c36ec283a748c1d2da6aa582");
      Test_HMAC_SHA384
        (Key => "82af0ac2ed6449298b517034353c3687889b4de0ddb5f3597b05c4e70cdfd2274e56f75a0b5c6aad4b2b91bfc8e4165da2763d9054c275d9e7fd2dbb6655e87a91d79423d59017cc7cf22c1d227a6d0f6890b0f4ecaf97b878c5636679dd09edb3fb88253447790d866ee8572946622640b14f168bc3837d95270ff02fbe5d09",
         Msg => "5ff26053b316d68f6de5b455377095681da77e47ee2664a4e552ef1988a57e17d1466b1f8cdd903400a50a90d1c33c9625d6170806cf997a080394062b7eb142029ab46f15d102f385d0600aeeccfdb89119b302b3f98a5d40b27e67b4e382d53b17c4ac179b33b5438d3f2a5636dfb6a99ad99dbc4c3e36d68733a2ec7bf7b8",
         Mac => "64ab6ba0015c5e2ea69968f4fda578dbb8148557efd3023d");
      Test_HMAC_SHA384
        (Key => "e06e730847c21b6867eb4b12f6d02142989ceb96ba11330bbe20f92859b63f793ad8cb3fedf22866fe6ceeb7617f434f1147a250f819dbd60f165b2dc600ae41a64d4255357a6ef81aa2b235814f410bc190bc1d3c4c41a987d5a4beccc0fcaa6cf562b2e802f50701b522f51ee9225cefa0c36450526c6d70855b45329e329e",
         Msg => "563dc6df2882043efc7428278642b2e47b2217ed01f1cbad64199f890ab84d1fa9ff51cbb7d8fb7022cbc3754222dc0d0c4b0cbc887fba1785a149cb8b69a4e011c11a3ff06f6d7218f525ac81b52a0965599216ad72b894a95f8e7903713438f64dc942bb9181cd44baf7d42d45c55ff01453045814ecae381d179d5c1924ae",
         Mac => "93bad5ef741085993a7fc789c4ab1246cb74190a607e53ab");
      Test_HMAC_SHA384
        (Key => "e21efc602d0824748c60fc8e96736c8618ef3a96b5f4d30ccf6e4942aba398d0cf082d00af59a98389e8e2628e362a3742c0d59c251bf5e493436809e93115e6e9ab72a660604a7d0534bd96a5d9884c7d9f869ce88d77da3ab001a4ebb3f415f8b0d23a86468fcac8ec951124840b2e9134577e4471e1588b5c1afbf952bec4",
         Msg => "6db044e59aa24693ab56af087e875f701e64d8173635502bcc4204c22bf0ce1e212efa306b0f565c6eb8887c287da4276547fe3336393d789f93b1d790d6e77c16297a5fd3fb2b11acea34b5c1e3da4ca28b4237c0de85f62116063658cf040bb5686b7ab9acf03accb25cbb320128683cf84b2abb6e502dba95abe66d244d55",
         Mac => "f08474f9d4b98f704d87dc646019649baecf154e47eecdea");
      Test_HMAC_SHA384
        (Key => "9918fae56359924aeae4d6111bfdc8c3ae8d7ead087526d95f22473c1f614a318c753826a968c595599e8e37c5b09f74fd77381de266d15d431d5bed463cc9880a75cf9f8ae6e94dc5a5a08d1c9c09abfb978ef8bb9bf0c2c77a8d83fea4df59594046b6ce7b07597420947de76a0e50ee1608a65bbb8eef335e65660f41958c",
         Msg => "2c46d9a814f4d8d35b0d042524b44be371765034a0c4103135a7c53bd9af0b91a32d412197a1329f6c76f4d593ed113a7458e5c5fb88470353886c68f18c07e3d524b5b40cb599827a2a43a8d6e7d7d1f6fe6bc44da6b081b2e9d58c629ca8894994ff097d1756a40c91b948f788e5d07ed2aad89e0693d0d930c95035c935ab",
         Mac => "6a7ff320888a5e69c9116e4fafd805c83396d8eafba87f29");
      Test_HMAC_SHA384
        (Key => "1ae62dc371078f8d84baf9082bbe3c8ee5ece05e8519709f283e19a26ad77468da889f64ab069281ac35b0677a8e9dfaf3c45024efa769d52b48c448865e4e8770e817319f14a97b03609975fdff5b8fcc7e5a5b48a74894d2a6b3608b6adad2c44ebeb3b6f97c827382d9b91dd81f525662288af7e2b8e5059f1072e1c3bf50",
         Msg => "f54b64fa04379ca25e753ee942d8205ed77f382a6e0605e908f92ab8188e5d8f8a937fd203a50c226ba3b679a9624d76ada2e2f5b4412ce3c7af2b5185a20ac6230b4adab1481d009f9b10a47fdbed760c69e0056c66d88fb2233017a7d98fb9ca9b0d3b958897e4024594914eabc805fdbc79811edcd194d03e8435059cb30f",
         Mac => "42e2597c6bba6c32e539294bc4842df8cb3842c214b17e47");
      Test_HMAC_SHA384
        (Key => "14161340bbfa1c4780583796f70731d202eea44297bcd428c3d9d752ef9cf9ec63be5e98080ee9c172675d2b1ddfc2cff7420be71fbff545ede032e832c0c7d1c178b3132edad12ad562ff8d1e698087009c9f42c4ad95250c48ad5f1349a6c4362c59d9b4c49c2ab23065e4820c339f24e4a97c0dee7c7028f890df1b9f5e6d",
         Msg => "6f24fa08de5244f30173809f1a141a9e00ffc2a9145f07e67726276b7aac25fe56981d1e1e04d548f1dc9473748737dd7fca810917e9b3089d0f5cf944ef73ccc9aca34b5ef6e65ae777557d686d3f9cbe9878038e56f3ad7c0d93c29dc93f5e2e2635948671a0b3490a6cc7df0c596324304e9e61eff15c7ce774cf6b80b13d",
         Mac => "642abab13c7678baa4460e4b6dec2f4ea84123999576250c98006a8a0a06eb57");
      Test_HMAC_SHA384
        (Key => "8bcd182e78a9dc1d38ff52958632a22b739e0641aacf2ed8f8f1e4a50c88ec667b622e7607c9179f20fd3c30abe1405003f4f8923d83cecab11d631eb5487960ac720f9b402acdebeb90a392bc0aae4958395bd43f2cced950d385f290b6380127e604c4ab34c9a9a1a2d1e34117b2bd7a57752e3631f7aedffb9049223bf3f2",
         Msg => "803b54a0a9b44cc935349e9d99af7c5aa600644eff8b3c9dd021a03fbd247b4819ebd46c5967ebc2c80785c87cda84a888f4bab97312ff49e981819ab13b5c2adf546b374b945d8341660b557af008c04b847a271d3729011dcfd6da35e3ce9a3a3dbf0a6783c9940a17d84b7d3b322b58794ca1e542e24ed4d546083062f921",
         Mac => "bc08205694fe5bcd786c785a0731b7b737a67bea10528bfa33448a7ea93dff0b");
      Test_HMAC_SHA384
        (Key => "e4f9334635a1a7e89bd037227007aea379879dc96bc2feb8ad0f17aa60a1a1869dba2ab3fd1cb82e5fc1afdae5cbf41840be53982eed1e6f40321769e1e290a09400d14d7db1badf23f0aa4a74839fa20a2e9ee8ac26552418c8ffb3ff8b88e35234f1bdbc49f72270c7ef1a2417f5685d3f4562ee56e9ffbb3a9532c385cf76",
         Msg => "0dbde20650041f568722bae9e11fe833d02f5d2355e4b4fa7da3105c2c5504a7195eb0851ad32dbda2e72c4f87a7d9bf09e806b1117d85b6b6add56605e402af02a8c66ceacff439bbef1686f61755eba4bc9abb97f6f3dcf2ed38d6ec8dee29d0826be448603b73dc21c3b9b6d5245fa895636b70b9c6143a4b81d466bb91c0",
         Mac => "1a14d543d1889cd3ead1ac7743944b24f55c30d1f41b220de2dcb4beef915edc");
      Test_HMAC_SHA384
        (Key => "5dff263e3e98e792b8035e4c74531b472d6c4b8e12cd39cf6cac150c8048f594b77b1932fc8e73a46652664e176ccf3064f142163633960eafdaa31f11364a38dcd3b667374ee24b91685bcc885948090a67a792bab6d9d8956261e2d5cbe94115308545b7803c71836cc52d90c18ebb68f5036c67ff0c14646cd7bb94b0d995",
         Msg => "a4f311c6e485a66d0a0b6c4828dcb677b722519f93d2ad8147e23ed28bb622460bdb04ef6af740c587004886ffad46c0f32a032b0b10073dba9402f9c4ff6a08fe5e660a557aeb2e120a24005d281883ff0287806cd2141d0010aab189e518d706e4fec2aef5edd03491ca614a3573e96410a544beff1e4aa0bcfea4e15373de",
         Mac => "950afb4f2f0d973110b4b4799f6d9650fdfe55f6f5e47788dd51566d3bcbb454");
      Test_HMAC_SHA384
        (Key => "c5317735b9a564d1fbd62bac1e999e61199a09174a4d5e10bb278f7fa30d3c9a300d8ef1834c63fefd3fabfdb91e11fe5996df3806bf1ba0b24df6baa00a68af278414a1b302713b0cbd2b8cdb4dc7156a628720abb48d547c3d428729a5f9d332fed0ec4fb1d7b0b2b875008c0e07cfd264c9784116fa55a05d3b8d45c6392d",
         Msg => "07a5696fd7e2e98fdde3edae3cd04d5728988e0af0e306d33b49412191c1a4d61e5c509bb3334a760e9dd89e5ba62e8efbbd495883ad1c3c08cfea799a7df3630ec952b6016f262a1909f0478e823c7be9cd846a0cd7518573baa3deb933933a5e563768c780c6d2868efc52dc4cc0477c3005e79249eed7047235f9f8cbcd85",
         Mac => "027e540cd7894b2043f77f52efe05495a035c3dd71bd1509036bb6b663818535");
      Test_HMAC_SHA384
        (Key => "383ce7f3187ad66c1d5c982724de8e16299c2fde0a8af22e8de56e50a56ac0fef1c52e76864c0ad1eeedd8907065b37892b3eca0ddcdf5c8e0917dec78fedd194ea4b380a059ccc9452e48a9eba2f8b7a4150b7ba17feac83c61604c3cfcfe6655c2be37ef0ae6fc29072f9b1cfb277b64a8d499dd079ad9aa3d5e9a7ccbec8c",
         Msg => "e3171cde18158c8e46172c051f11e80b9d2c1e19a1d15d11da036d2de8f38f35c1ce05f654dad5ef6dc1cb4dd92dbd1aca9412b17d568575190527c2db03a3247053c6c7a2a93f2f37c3a32916fcb402ac1fe2f68e7912eb60329f60f5dd9ea0b74d673b4aaa51b66cc5bc8220a9552b0b7395d21e638bdd7532dced7fa60810",
         Mac => "a4ad6471d8b0566987d13323f2afba3bb218c71f43aeae38ed5722a60e8e2899");
      Test_HMAC_SHA384
        (Key => "c4d6c342e2dbd2f94c2c758a6c951b38c5a1f10a92afa87eaa48787ca7b0658947bbc13d13e2f2f73e9675cfcfd523cc03fab358ecd981f05f0b8d200d87c7aff0728a17e9396637a7dc224cca8d011e4879457710e6f2d9ee7ed470afeac34685a326b6ad05b6234ea685eaa5e53e945fc6ae5146fd83a220485455d402e2b6",
         Msg => "5404e7d8e805f4c2343b405a3eeb08b5527e26163bdfe66cba25161b30725cff9e1acdaecf08bafed45ecdc8b15c55eb5683df93d1fa06bbc1308cf00ec3a958d7a1a2f4ac6d9e22fe24b666d3004b69be9c9c420f5a97f54702f039cfab717fe9df912fe6fa47359ad320bc0d9e9039731185ac5ec6422333e16b7fdaf25c7a",
         Mac => "0115eecf3b9f368cc10c439b985accf2a1b251d74db0aebe3a30f2f0797ce212");
      Test_HMAC_SHA384
        (Key => "85afbf16eb940e704877b4d16a8284d450451bab31ab0bb6c12c3954af4583fa7225a68245aa5fc5708bd16bcad727027c9e7a4e07edf5e0890037ea3cb4f8523f3bf0059913f48e7b3963e7c59ac08fcccaa0dc5af8c793f7228eb66785889d74586448eeb915f4efe831ec63b397a2c83155fe33b3c9f694f8065f3aa07803",
         Msg => "55ceb7328ec045967807a80790b5f55b2a66aa1f6d2edc2c9fd0927ba3316c3bbf0c8820a3e6a5fda7458995551da1af278be86891c509cd4252c8a9a8769e9cb2f1a36dd9e9b2a16124c74ddc7aab28f18ad4e45bad86bf34283f5574a652b8b5e5d2c239afb1aa2d0c29d62fb65bf00fcd373cd2cc9b29fdbcbf2610a7d0b6",
         Mac => "e78a8e4d779521ed3169a7f30ffe84e8951752b6f8da75ec5e024ad00345c723");
      Test_HMAC_SHA384
        (Key => "c9b74b2ba807d65ae62728882a32c4c0a0b2d9019fb50ced8a2477c5f451f29507cf91ac26866e4fd106a8afc91cab1875a3b26a859d8bcdd5839aa194d921b4a504bfb8456036f4ef8e71397c0bc5188f07775230747e90b75d8b54ec7947306c00db364fbdb6af07658a108b279829b6842ea0e9616e9ef85a50c8445aeb71",
         Msg => "1435f6f716806114e6df17b4fef3089a61c1f413820675e161ca4078f738a86dd4ad642b070f91e83e60fbd72e93989f359e550d3ed01505e665f7bfdd58d8308e781ac502bea35701de285c7b1cab5a276142a26a8e1b3a7a10bd1bc3b5909c8abda02fd0359e4b798028a9ad3749b37f33443acce78d6766f319f472f7d79b",
         Mac => "65bf092a7dbb8cefb9f05bbc8bc863b45909144ac9dbf327f3a6544e4e3a37cb");
      Test_HMAC_SHA384
        (Key => "4079ddf786334e067552706c25de34223844698f0db38e0636c7e4912d65c8ed42e640d5d877d484d1bf9f7547c3a56d7d0767bb15f6b5be8384c4a9c11280834492237230eb0738c89fb8fe28ab4e5136affa6ad64edeb25dd82285492644362fc6af54f459902c4038e58f305ed6d64b824922b883b1e9ae0926ae2b6abb0f",
         Msg => "8d8e0812bfcc18ca2a17d5f8ae9f42e77ca1336b293003c4023586c6a0b53e37bc52d2794415bb68ad6a41868c6ca6566063a105b28b0e4f6118e3a13776667bbfd59d195be5065291de89c0a6c4ab216ee904fd62b3f38af39f90cc1e86e2004120533b2dc6604f7c7c95ee252eb9124d3a469b602f1c3a61d4758f7e6d1c8e",
         Mac => "f4915ab7714e2bbc8a7a1f270768fb405fe2513762b2dc02c35f6c04fa957940");
      Test_HMAC_SHA384
        (Key => "e0ac3f5886bc45db77b92113acc632721b14bdb7db6b341c8806b8d1e9a4dcaad0dcac1542b1ee4ed866a7d66594e121d979ac8e6693639de16d305d6abad2234fa09e812e56c4765af1d4e3807b813e8b46a48ac47f84873e065426717dfd3f25a01e8692d451bcc502b12245a59933f722ae923f591f4268792b154618e467",
         Msg => "afc595de08e9de221a59d897d5180af3282700e5184cfbf90f12e7bb76118d1f856f0a205aa780a849890bb07483f7a89b1e301935cbf989bfe0e19f54def3877ef52e984cca3534a47747f0dbd370f583f501a784f33f846fef584e0e559b6c405ee78e03d96490d32a72a13393dfa489b25dd62e4b33b1c6483211cdfeeb96",
         Mac => "0d9556246eb7d1c36640a11584cb1dd48cf5adc66981a24b81897d1db68f0b62");
      Test_HMAC_SHA384
        (Key => "0bfee65c1f56629893be1addc27564f1e81c6a2d8e5f393849d81415a4300e605b88d8d4ca17d711a414799ce8d6ca28113a42148e45e134710a7fd46bce5dfaf86bffecd7f23ef2bd94995d4ac3ccc83c94a49ee36811ddd5cb7d19e29c5cc34a6f04ab2e2fbfc445081f27d083925bd0f336d47611efb9dbe3b6ebf1e23442",
         Msg => "40498dd91b8f781e78329ec1950cbf8de15e6ce403c124561e5fbe72546206db89adab9f69ca59c5ac2422259877227dc88463c02d09feb152f083b1e4c79bd57170ec3c701a3da08270db2af70f3b8b943ee04893d97f55ec8f62e6d34e0a8282fa185938656ed7827c9179b9be51e0ccf3ad243f1af16a74a321b92ade9a09",
         Mac => "1f87f065d03d36b93280b6026bf48a834da01cfafa12b90c7771377f5d895915");
      Test_HMAC_SHA384
        (Key => "42aecfb0ed85032c792b74e759945c06b1a7154ec6e32ce5b448b6585f75e7e2ab0ee0ecf060c9d0a84820e26b5050b11e1c868a6705c03e630327259cd09e63354a9b6a681a35c133937f034ddc152a5f52f40d71288f28a2501f9c1d9f3a76482ca7343ff9718680d53a51e880d2f9de1108e0ce95c02ad9f946c4ca2ae2a4",
         Msg => "504ec4c48effad524dcb70d3a2816dc074805a81dd84cfded2bf07b6072ce5f30d2035bdbd2235eedafc53c6f21239e185f307656a2edf806d67a7123da90aa686fec0a75a3d10d1d52493e501a63aa1f78692ef4725475d9a99e8cd96fee96d0211eeea2bfb47e1866ab69796e679e9106384863e120f5ba17d504fdad38a31",
         Mac => "e6c9f32e14fdb19600870ba8ebf650e40a85fb9a89ce7b48e7cb7e29cfd6007f");
      Test_HMAC_SHA384
        (Key => "03aa9b8a2aefdfc59f5c779e720e1eb64b60d3d75c0b7738949297fd16dd87fee923b0c9f10e2aea1e1a8e6ae33f0595eacfa50006a1fecb696fef24177dbf0c9a7b685ef7ad360de24991ad2e2117358781ef03635b592036a189c6e5f3b51f7e7a6d5026142bb653b12b6f3bfd7c1d8c3f58e65d80b1c064f10ceb6a8792be",
         Msg => "5619fdb97cbf05f4174e787d13d2be6f30deb3835589a03228b76b1adb9a0aa348783de241ae7dbe21f52f51a7e41e9105b6282f334e38bf8978741a8d72b7000aab410262caad9f24f224aee144d1fc3ca6943541c3fb08f8536e86399da9cbc13a70e1861b7de148cebe5b69fcbdf8fe37605e26f2d2549bd1c1278624ca4c",
         Mac => "09628d811b3285dc5349305d8fe6a868b0b9c5d9eaefe4c1f9d5de250cc753bb");
      Test_HMAC_SHA384
        (Key => "28ffcb22dd9ef0e43ccbc98327f4d215a80520eb20f1a5c4a18db04098a5b398af4a498bf169779c2fa2327aa35622c0d402a6deb9cc1857215c522e53ed719af1a4d90122207924ef525098ee8f2f751ee3c15213a9ca705358ac35ffa02fdcb6b6816cb6ec7ce6448428c34fc6819d50507a2d74ae4175fd2ac53ee5e576c5",
         Msg => "096a4c817f20206bd71b682920fcd3fba6ad31cac6ebe0c4000287474ed80700b42daf541921b0fe55f7d0fa8b1862a2b95b75188d834ce37b0a0edd0c1dbf4c79e76f4f7812b17c568b4fc746863ca5f9c3ca726e0f1d100c0de0d2ee3636987e1ff43b45fa0d2b01604e56f84e4b4c8d6d99a111963d93db9565ed9b2d562c",
         Mac => "c1e67187124dc3e16d3df7a39ac7cf2013204549302f66e98e8c3e63b237bd59");
      Test_HMAC_SHA384
        (Key => "665812a554fe084339553e3cc29dfa8996362e2943c40568788bbc61761bb3c2c132c4cf1bded3aab2e2a6d1995bf7e875a3c8b97976f7799453124ce8256c0c7f23714639f53686091855d56183f77feb8b321a7a0496c340a902ab41bebcd307f3c113988c5a61a5bff050045d21d761b5145430b609d0e5533485682ccb9d",
         Msg => "8df0a3673278e26064cb6f688022ac2a0f2e997341b6edf29781663cdf765d1265029de768ba759dcb420c900d6df5d57ba503c4a48e5fb30ee6d70527b079647e91614a337acfc6ad877d7d8a272fefdc7e8bfb92072ba5347ef118d4fd9ae7416596987dff176371636937e09981fe9a7fd822f26a7a507110597ccca6e825",
         Mac => "2031305f71c69ae3ea4d554727f83c7d9c485765968b19796bb0187ce04aa7410302e2fb09cf4b07");
      Test_HMAC_SHA384
        (Key => "7108c0d1e115bf9d6131dc37052b760bdde7b43ad5b1828fdad1d6b63e6038a85e5a816a82f4e3f7042f297bb5ad40c17cc3f7ef40d1037108ce46336127511301ca2796a97d43d95075ddcb7d246a9af552626b966f454e8328e0718138cd94a18139bc205be92c8b2c7f912639fa7d8fbb7d169f36511091062cd8663ab412",
         Msg => "2c723d78a66c536494cdf37da0e43e2e171a09c79dd5327e209c34b40a7bfa79bba9f151366861381a2dfde5d501b94c1427db667dff5534a12a52022cef0fe95fddec97c1b2c353117c783b7efed1d01b5588b58ddc9fb4064cf402782815c4025855d1af1320ba5f038b0805a42fc413ee383d3333b905384a433d54edb512",
         Mac => "826a2a11380c260873663815ff5e02201a17dedca1b20c613d0dcc019095b444fa0e96c8b2df5433");
      Test_HMAC_SHA384
        (Key => "96391b89b1d2d11e09c44a069c698901bc159fb5084034f29ae7633a822fcb81734ce231bda18d717b28eea70e157d3bcab65b9fee9ee38cda02818e7c63c7c20c6dbddef9207973232df06f4aa30ce6c6caff12794fd69803a2510c349df2b8c76654994d96beab679bf867385b5d891a193216909d369e7d8f7abe932573ea",
         Msg => "b4e7da4b48d74985480b4ecdac6cc6de523192614ded901181ccca1d6d19eecd4704ff694ea349575c369a83baafaf043972edfc7e5952bf9efbaa38eb2e06890dca6af254b0c6f44c0b27b692d62fa7e79fc365838a03deab987fb58629a7e72dc084ae0107a6a541135e2ddce82d1083407b6503888cb4d22cb15ae714bb2e",
         Mac => "cead49b07d7a98bc40e3f9e484bb562fac1bf5296f6456f22196a4570924252618cbe524a249c477");
      Test_HMAC_SHA384
        (Key => "0ca2ed9ccda936e0e5fabd1eeed393b4219d516a767c59a40c245eddccee27504a2b8ff8ebb8d1bb4dd302e3e32cdfcde03fc9e557e20ed2a01a6aedfd33cef87d105f0d21bfc2d43e5097f922e843ddfa11f38cf454def0a00aca449c6fd1ca70f865c1b7e79292801c834af32e484c38bad64894fb4f67d59b84c8f1c9b930",
         Msg => "4f472914ce9cf0ac7f663c06f3be53a1c2b1a188da40ad7816ab4b4113f0126e3f8e1028328ebd5842c42e0c51538b1cea6fc30d8d677e3546e2542084683c332925478fdeea8e39a9756877c1f2e17da1c268485b7ac8cb2f2f5a495cf178023695341179b84a95dd00540feaa53d0b0e30f803ed837280f81ac5824190ae22",
         Mac => "5dacef52a951847b5b26922bf7cc74c4ecf3708da5005615a6df512fc0edb1485bd8efb840c90fd0");
      Test_HMAC_SHA384
        (Key => "0996b05111989bfc10db56819c2cc6464d52e95dc3fc0211ebf7f7bf7fa4f7e8ccaa5f83b8e8df9803aed90acd2c09b5592a6bb810fa5914c9abf4774780c65203a0a6312c0fdb4ceddd8459ee9e37a51d1ae863ae450c446071ff4803c2a3d337e24b0376f7d74155d220160669964022882706a5c363c83bafdedaba52d693",
         Msg => "e0ae386c4a7222433f63230fb8a59742aa66c69b2e712155e000c99e84d2514af07ec5c92607eb56c0b0c87291126691896bd513d9397075580861c9258868638ee2d8d6314ce21f61dc151fcc99264f5ad8edaf58c6b1ffd541a5324cecb2208482777bb56a8f04ec8c12feb0645ee3e6541757f23f6c5a1f539cc14126b9e7",
         Mac => "a93d059bd930f765514c55d0013d96bfd55abbb0c0432e898bd20266b64605f07fb9824f6c50f129");
      Test_HMAC_SHA384
        (Key => "4f36c18e476c006a2d8e603e12f719738f6f262d065da3202a387aa5c23f3e0daa6a57351aa0605a2a2acd2f9668d12dbfc27f2bf3e22f2eee202382a13e6a0a325605d4431049f07718848332d0e317a1429335fb582736064f3a56dc69550aefe213944b2682d41b41cd616f9718d83cd5ac74a42754df78ac0648fc27c6b6",
         Msg => "d32f136a92049bff883fd5d1d649162da47fdced7032bc9fa5f29be3700c2115cf516b2ceb1900e2a78807167910b76e79370e40b79bc6b3d2338521c6d754c006035282cbd8a939ab63c2ff6d22b5d51cc4048a5a3188dff7caabe8c2f2d8b59fcd3032da477f4cbb596e555b88faaab5ae249300fcea6a3d4077000c64973c",
         Mac => "42311c23850d5e3460fca8d6870127d01ef4932ca6899632b92c895c0fcbb44e03abd9e5e753b983");
      Test_HMAC_SHA384
        (Key => "3f318aa4d4fccb3758f58d2d05826c40fc4d38902d9af99876d830610f7560f525f7cd17c5498431fc529b8e3dccbac90254db86b6bd4d5fd3aaff22485cfb391dc8316959ed76c02464ccc82939e4013ef9e18e470c5f2f5745b46f19b8751f6fcc3d025891a9ca1753a743926ff1cff865d412a62f36ee4cd1d7b24b32d78e",
         Msg => "22d3f7d1a1858d4cbec9324a3e1dfbda03abfe12dfcbbfaeaac8ebfb92e749f4b3a5edaae841afe9e07adb18749a2a6137b3f1124f29994384704fba9717fc0bd5067803eb04fb47fc7cd439f1805d1b110e2e77d19291beedad362fb73528faaf7d00a655d659b03b5583755ed77c51b6431b090c0f8f660c0608239b48b40a",
         Mac => "40a610d31345105029767e5843d46024239d903a744fe37ac4acc7a984330afb3e388462db552d78");
      Test_HMAC_SHA384
        (Key => "5051b7f8c9c7e9e1d0b55d0a05426ef23e0132e6e5c5fe759bb72c2521a51b64799d78c148bbbc5c7f3ff69b3ae2cb1fe96bbbf7ad7da61305b38efba9ef9ec1b6ee6b330c207b56f4b7041007fef5254bed3a659efa3c235831a8e82c8772694f6c19b7dc9f2cb678460dd0323ef5eaacb0389780e5cb8cdd5b035571189f46",
         Msg => "daa147d9448d45d7a0b362127cbcb318ba4e57608930078b94afefe97940bc3f7c66f7c87dd6917927dabf896bf308312cc29bb13c28e79388ad66338f1eb97f197afafc25104e0a23e1b968634b37facee908cad4b54b4ea56fcee9a44325b318a6f97d2581a310fc91f9b64e0d68fc068a44b5371d5b4253bfd0119ff52764",
         Mac => "4aec1c3858a3ecee3a73be5211e0b12331a502c4b8dfed805f0b2ff6fb14167eddf5cd2fb1048ccd");
      Test_HMAC_SHA384
        (Key => "7cc8dc6957f74970997160de77a2aca2721a4af337e2f143c3102f6eca99f5385a6756f6bcab8c8b9b753c966782fbeafc54103f7f887b278965374388b1bdb662c8c9da5bef603238e512a0a4bb7dd8d4e6121567931c0b903afd1c7676bbcedb14bc7dfc69ce4db9e96b63f6f63a5541f6d8deb5a8d9d71eb80a625e91f969",
         Msg => "9954cc20df9ddf553407ab15c6157423a2b247e9d5c83ab2d10ef519132271c103d700471cd08e754c4e26b99e46b8d516b719d7dc3a4b4c9edbffb12f27582a7486f27780cb2323fe0a80fecfa9a3cef5ba2c42b0880627e670ecdec8f32b0eb309a99654b726c610e3c2cea368bf760766891097dbf3ab7478c48a28ad72d5",
         Mac => "9a23a86d0a12817e32816a5ce93c9a0e80f01862d06c5b4d53d5e8329202d30e5e3d0117cd44951e");
      Test_HMAC_SHA384
        (Key => "06e7210def086f58b210a7010668e0d25c52a4421c1f4f4832a3b871c9e61331561c1676d9d75b83607c06fcccf3a73dd7a362f0569e4ddfbc181906e01ef5ed0085af3505201c700836bb3616329575309d6708964a038b46d0f46ebf3d61490a09346ffb497ac6b5250dd66c8c711f6f27fdb0658b3bf5d6b291d1eeac20ec",
         Msg => "4b1a16d7a190920c470b13f5916893f06da3af78849a5b018213d423b101d6fbcd0310cf142ed5f09c0c14e5e9e48ac5bf3c36e5359d0db30b96f0e23d03dbc8d8905f040d7852638493c505f38f36bbee7d07b401902f59fc2230758ef8499915c7ecbfb5f7722da7a60e9cd4f0ff9aa36e0a2d0ffc28b9fcc07c23cb688737",
         Mac => "4121e1c375037dffba6eb6814d1f512a81d6009cce96562ca1f460cdea0b8a59d0a3e3c1950f554e");
      Test_HMAC_SHA384
        (Key => "1731bef761d689a566db84e07996b85523ba1bf7197f1c476cfd7dd300d961fd3f24a6fe0e80742b00851676ca630937f8c8532dde0416bfd06b658896fa56131a3e59e36472c8b7c8e8bf0c5eaa2de2b3602bc3be748d021675b74162b9b335104780ae4af3acd125cb25a81cb24cdebe4b4bc3a319a896a4e41b044b5e9dec",
         Msg => "2726877bc4282dbda4db6564fd25c8bbbeca5cbad39affd7a5e8091ee13d2d847b4ea079f22c7dbcd5bb69738665737b3e0f3dfd514c6142b4d10ec8bc2af29528ab5dcb62a8a37d02e9c2c1945844069bfd67a8d62c7cc2c1fd8d445ffd42453723059a9c0665a7324cb875ae660505dd7b21e4e8a11700d653cdba5220e53c",
         Mac => "61b98a431a1b55c2652520f2181594ad39273da29c4ba1fd7902af99d234f5cb24ce75f41bf0a5b3");
      Test_HMAC_SHA384
        (Key => "c071c63d6574232cc3183b2171ace81bbf4cac24e16df5854fb69f366b12bb9864038f665b39dde9c563696c1145b5f08a0a0f217edccd88a0b3d801ab6a677048180db0329df6cc987b6e72c3e8a2a4f821abb1a000c864a6d1eb7b2162785a3359490130caf53c03095219cebd389fd13688bd8d016d8129b9e28b141f75c0",
         Msg => "0f66d0b45095ae1b59fd2db7780135a1f52156f8fd1e5d29df5f256d7b94b093f69976ffb39dfdf37f83aa0d0c88d711a12726e90f3a14eae761d159eaa74f2ec1639817ef5d66c00332ed5212fafc3a6427442b6eb0f76600709639c0c904c5d78cde05ea1d0f0c4cd29e8e729dcba2a7eb5bc600cb302493531c14e43ff7e1",
         Mac => "06c3568bfa7c4af9d6f2900c80afd15d6880056bd42d38620fcd956d36555688f2634ce632bf2006");
      Test_HMAC_SHA384
        (Key => "f5c15429b2ebf430282b8e92b0c76162a4fec17416ec6a65c2ad14db42c5470e81bf7188721536290250076d4b70f6f20a8ec83453c04c9b833decb977c282ccfb346d8b8586e31f24dd886fb3f240a052b842dc17406f5300d9e1802c7bc6ae4b666fba5406a41a761a3b1e5015e97664c457f5c932789521c91bbacbb9bcbb",
         Msg => "1c72ecfb8439d9ae3ed4eff8fff3aea771692ec3852f11b90aacb6b87f33af5c25ce768a593a5b9b2132c1bc05f18a9420f2d02876fad6fc88583e7b266b7c9985668ab79150ddc7844f99b0b82501f4b9fb31909f5e0f249b877f53cfdfd66d63c2924bd583487b90b1dd9ec199f90d660cb9c3a763a4776abfe1082296a71e",
         Mac => "f5dca0801674ad8f4654f195437367b1a9bc5afe198b85bf539898c6fe946fb0ceb19f590e68aa04");
      Test_HMAC_SHA384
        (Key => "fa90796c79d6a728b50d788e35b9345b109e5f8f9bd3821d44182fe6be693fe85fd45eb3c687ca1dc02d57376d7bb7809e05f85882574eb78241131e69720ccec848ee3999e720b62289c3781c15f0c115f24053131d92287a7908622f675385fe9731e4391e3359a2c8c4398baf67873c0c4068954ed6d7f569179a5a719d75",
         Msg => "bf92a10983b14561f1491d3b837724b4ad7105d91ebe847544a21a280edddfb9f595aead3d90831978a627b44d761030775982cb1094fb2110d2ce4411d10e0e555badb60978e5a2cbe2d77c6bb97388ee789735d9287bf2acd34c42ac3c1713e5cde94c70d135a5f2e375bb65a614641bb78c3fffe0cc901f8fdc4b6786c36f",
         Mac => "8dd24a94d6dff09273336c22b17f2bf5a040e16e08d04dbe191d8ad084ffa4e52abf6e8111c0b642");
      Test_HMAC_SHA384
        (Key => "733abf560d9f3733e221f37bd6219ebd8cc9889486a0f1d68e5b830e55f7202d5b04de7c0e4450d536740813906a59c7b960622d4e90475e5201c2c6d0a0dbd9c192f3022fc907dc9bd533a59dfd75f0ca8fb499da7401fe0b071c6cc0283ad86e8b05d0b856e5b1d9ec7e1943037a9f85fd88c27275a42080189ae96eb6c592",
         Msg => "76556fee3b6a456a0c64558a00cd88df726730c85428f796c58315ede6e9c76dea90fc926d7351d9079a3f25209b936006611f653c2cb01e16d940e982646c4129ab289ab774b18c76b2c33422040dd8f97fe2c911ad318eeed5b73e547d732e5a2e5accc0774dcb82344881ad11dc8d7249dfbc79b4622e7800e3b4033ec47d",
         Mac => "4213b34ec9ead8721f33585d1231393b38d1c1fbe59ddbfe2f2f2206910e38d1c964a71a92959f3e");
      Test_HMAC_SHA384
        (Key => "b619d9d07461c11bc9fb66117d61ed90001366bbffdbff583556777584b0d65244af5c7bdbf3b7358d7c791b966cc809760e57398d1896ace72d26cc59a6904fcd92365edafb8af7986c7d90b2af3bfdbcdb1593c78fbe8e3378bbb0c519152bf9cb51c19a02a12a8fd35cb6f8b3ac337a828711d6c8e0c4c13e1e6af090cdae",
         Msg => "5a81e711adfe5077dd8c8b57c95e8e1f3de39f4fc448c523bd3e7c72b1fdacd6e489dc0d2a34a39ffc6460c1cb962b7a94a30c04b5426a75ffcfc69f0c4ba934d3a3da2e7935d56d6b9079a2a97b016d653a35c2cc0ce19124f887a617c951ce4e58493b4209cc294f983cc20b16f63fd52e8451b1ad13bf5342275079818deb",
         Mac => "8b4258be4c094aa4056f332ede8c733772664b088ba22ef8caae7cefd77eceb35e83af8d9c1283cbbffe4a372b699c21");
      Test_HMAC_SHA384
        (Key => "e48825a5503a6afe0bf9a240c67f27acd4a8f6993834645e03c80c72dd370cd2e10071a3ae18ef19bae9d697ea9a4118609190cd95361907a7fa1b58f499f3f5e79b935f12212f437dde399e3e6490244aa1f5e38ba9be2433b6ce924f6cc49e9f627321a5df9343fce1b59deb647d9a3ae00b234414ba7b4e020d67173be693",
         Msg => "8561865ac2ce12832746f82584a4b98e7f4c3ae2410e18196f4e3b475c62ae207d3cadbb1d490096519888db2f3f18e13bfb86f62216015cab8ea491ea734cd3b791a7e45e4f8e0b98d7955bba77e0372d4738161e0d5d84765d9e6a0d05a88e1aa89c5defa864e9e349462e8f14b9993d7a78cb9dbad69aba0551582ddf6958",
         Mac => "ec780a915ec7deeba2c8c9e2ab15c9762a3eb18fafa2d48a554ae1fe6c4459da1a54e2d58bdf06fea0740098eebbb699");
      Test_HMAC_SHA384
        (Key => "b9280949918c582fa63ac4c68cc7a0e74971435e08035aef12f98397f9e51713161146a736666a18918c95fafc536c325f5239b368ce3b8b81dd412300ca77c29ebc7f542b93c36a80130a81b4444a879318bd9b4b4f37156998b7c604f93c813870dad9d7db0c2d5a154ce21e62e1f0cd0df9a0194ff794b1730e076d380f56",
         Msg => "9b1d9b8060067187f19e09e2bfe17c11d0092dc1b7b25b06c43bf2e5786fa7153b65430651a43f230b8b92553af1c7c8e90852f14c8724d0f3087d7243ae02bb270c0f6203424e3dea6989bf1032bcbf82c96f7a140042dc9ba9cafb5d439be5c6daa69b5d28c65df600952828ed847e01162b65f964ddb225e78087ad769b1b",
         Mac => "f9bf35de6f3888828b0acf7da8d2a8848c292a5ab9e6e2e3475d665d398e5ab424183e9beb4db0d7accc6315c53bf0de");
      Test_HMAC_SHA384
        (Key => "1dd0942297cba8157069925114b832018fe31f35450ef6e2e382f22a950abdde7a9c8642553c5410851e9abf370b0b04da05af9ad32e373f72e68eff2534b0b4ec67bfce0dfd545009c3131bce3e826f2e4a1baf90019f64e6deae85df2295f65d77674e29d44fdde6a024ee431a3e4975f888fce54ed75b25b27a46299e13aa",
         Msg => "8428a75382510207600c10573c4c0f6056a74a0b7cfc33d7c559b2d9821cbd017258299e357abf24032c932d9e7991bf853259cd6b914d00e71de7b76dcd514c7d702f991a4cbfba7e0625150cc20098868a414280f43de515ff012ad83fe5d50d3a644a1a112a5038636f166e6e8474c077ab72a46c2c0eb5c9a53aabb8a225",
         Mac => "8d032500ea94fd8686b465634d74047db687a1d1e56fc17100f40ea0f7e3288efbd016daffd5d3c32fc6988996292788");
      Test_HMAC_SHA384
        (Key => "3dc1c0cf6978292dc6389fe87e96335dcbf493165b528940f867c45f68f0db4092498f2fe33a516bf01304d75dfb03f2fd8566093a8481acb821ae5e352a4d90b4ad08d1dac65c3f98b554410a3398789f07a7f27bd461a11935c80c350b0745e916b41b16c3529005451a8e4ee7fbd5f9a1df38e4e9300964cb9ad22f3c1345",
         Msg => "b5e3eefd6fabee2f84ac6b7b98ca4493a1ef4e49410b49ad54591376c5e31ca4a5481a637ebdfe31e45226434e77d42524bedfa219e2a8e3bb0950db484628e2c462699f48dc262c9d2e7e750a5216e16985c735804b93b58fb3de8c26dcda6d39b8447b76104e66d6c8dcd77365f20f99cc6dcb1f4cf26af8df255105ad1b8f",
         Mac => "40d43eb4671e6840050be5fc38c2709eccfcc47388c380afd52331dff3868227377550420ff176ff97088cbf9c5aaa05");
      Test_HMAC_SHA384
        (Key => "abcdb92d96bd11e85ebc4fbd6f17dc8417701e188cb59bf53153620615a6a7b8bcb4ad53231ce98afe49645144eb61eeeda84053fb0ea2abb7cdce333d23534b3a97efcdf5eab09d8c4b598180ca0733740f14b5324c3ce5ef70fe51d09e454caddd48421411af48912af7f72c9b177b340d64e73b55b2cb62a4bc09d7fec6e4",
         Msg => "b5ef6f15a59e24f357e578b50c0f6016e9c0b70c54d1ca42a15b19c9ee125c0b4bd5c5001f8385a4c70f91a87fd7a66786318a1d7d4796531026719ed9111e89811b39d029f57dcf08048a3955b6e50d671741c61b9ffdd3764eed468bfc5dd09fea53ed8c9c155c63ebebd2555626efd4996171f58107a819fe162acc7a22c7",
         Mac => "3802d4c92f767fda5187cfee5eb73ae20b6bce00e8cfdde4879a0f8906ccba8a0ae3d4fb4a7f1188c3ae9b1910bd07cb");
      Test_HMAC_SHA384
        (Key => "56cac4042da649666fe7b1efd4f70f72b55435891687d728e35aee787a465be26a2bcd697a44e43eee59978e0536d39fc65d641bfcf819ac801123c8b605bfcf5a3615537d015fb6caf04dfb0e30a8d6f84537051dfcdfe33ea10d3bce73595aaf5563683dc601f88d139dddf6cbd83fd17473ef7e7c70f8a8737477c97770ac",
         Msg => "d292a7d9a314845d0468665d59ae01891dccaea88b59bd989eba0d903c8adba9ae40d89d540b7ece9701a38a1e794f8d45b5cbc7cbc5fa60caa7ecfaedb3b136dd376b79fc5ea7f05656eed1d5b196e4b40cde4335ef3b5e97f5ec41422dd41a46bf89f503d3a9cb29ae6dbbe41e8097501911a233a12798ebea34efa5bfee5d",
         Mac => "375d68bebc28b9bd0d7108bcb9cb779df000d15090ce6b188ebd3b80cab50c431929ec374c693ca4f08654ab378f3648");
      Test_HMAC_SHA384
        (Key => "a797132ce5971a3a9152f0e3521f9de381406a2be0c53ae189ac1da7244d23205df66eb096d28b84d80f03d3103f2c6378ff454e53d7c206dd62e59782af8e2c4ee654d5a52fd48734cf496527945e3d9c7440565871f669b9c0f5edec29ef9760b1ed227b779d4c8bdced21ffe6d87bd7e780ca59597e11060d7631cc85ee6a",
         Msg => "30accaec827d47ee5aa21603cf62b6c3ee29331cbb7d47e97334c5c614e437231f9cc6989dd15b78609b04a98b2299b355529f1609d76ce151458c80b59664d65fda158c212aa4a8b9de5761530062314f00c22d45a86a9246539da0655a9bab76d07f6f166f68a4ecd1d7d22ee458676698650776da8723d9c6becd2d1823ca",
         Mac => "3ddf47cb13e49e5cf054bbcc073636f30b05dc9ad979a017cc8401d3f1f7f83e3034c41db41942a671b3d3dd706b3619");
      Test_HMAC_SHA384
        (Key => "657fcef962db04bd269ae5fef2cbd5e6558d072946d235e8706394d4cd250796769a926fbaaa121b6da42cfc82808474dd672f9362756af252bd8cded78d39b9ddf4d99e24824844934fcf25d03e54df0d83cdda2563fb2be73b54b8b1c4419d429589cfc9ea0dff41a3b7c20190adee8febca47b6264e5bd8e8d4aa8552850a",
         Msg => "989d5d6083c85c2b09be202c60f1277b8c5e471fca623b812fd05b218d42ab8896ac177e4437fd7c784cec64e1eeac701f4e7e682899a419eb152402346cca50d0486c0df11f7194d4519448a070e68592de12d7579ee56ab9640ec27eee22ac8d97e375532ac15965f4a13e671ddea32c388dd31e18065ee1e5a0c93370bb85",
         Mac => "4f1283e5446483a4f8237650572c8a7694d5f8e34086e81cea1f5bcfea345e33dff699a36aabaaf95fb2e0ec6e0e3b03");
      Test_HMAC_SHA384
        (Key => "900f404d396f4bee526db4c9be701896a60d85bf1a203b15fb1cafc1189fd67d974a9f0497cfc2c6134bb8e109d70a4ddc59cf56f8a17050b4b1af867c5be8732f129635c6fa183e3741b64d98b2df9c8887b45bcb7fcb5e34312c13c8a0a0b6200f2cc80f17d8bd85f6b4f5b32a1ded703f3db7dce5d1a743452f50449587ae",
         Msg => "7eaca1335bbbc419f930bb7562b9090f50023d84f7346cec26bcdeb98e4d08e26128ba42209b9a3baec7d19ea8a704cff94e8624a870cc8ff524217da5e89afd9ae64d25a676beb1a1e39aeeb972a8d70aa0fc7d6fac6eac97554acb5be549044e6ec0a5965418c6fb0b7e2d3e22db6eac810756f2ef3a8a33d7c36c584bfc3e",
         Mac => "52c63558050e88a4a934d389c9d973f9901f2db74428d642a750b67d890910d7028c26dfe1e76010a9b12c95dbdbbecf");
      Test_HMAC_SHA384
        (Key => "3a9f2fb04c0c42b2dce178313786aa7713256c96c90ce2f2be53d5ff22bf054cdee7c1c1c795b625186f05e21fd7980d360fb5a1f5a1d30ba6feadecf965961afa060ce83f688fa76608b46cbf4375144575cb86d3637f3894d63cf5bc89eadd754537ad1c4b7640aef2ad567d91e995289fd5cdc9198b807024aaa2d1f4a99d",
         Msg => "dce5adde1d996c50f9b061ff8777f9b0450343475d675596272bec73eef9520df7988580bf1f95a685624e3008b117f692c21a8c35eba5165594d05d67ed6122f7dcecb2f03a3fba183efd5dda3988844884247560b75aa88e1c9bd573642652e5982c9c37523134ba2cb5ac837914016f33ab2b65353cf3dbaa93059cc66a46",
         Mac => "27808650572d339546aba818c11e07274bcbb7ef5b46f5a2917d7a7014e3ba58b5c162d2dc4ba6986eedc62a061b981e");
      Test_HMAC_SHA384
        (Key => "407cca4b390ceabcb37c48dde081d1b53ef41075ca30fffd71bc1da2c72ac02ffb3ead290b53e65834fbc382ade6447a9405a65a29ee340c3a83600fdece12776630403691bbbf9bffdc5918e83d1f480ee90030f0b29bc641d052af98caa04d699aacf9340c1e8dfc673126fb4f092894ea48828942dc336eea1a0d5ee511b8",
         Msg => "aea7ac414ac7b81df547ed95800cb443ae141cc731a2710cd59c10cdfc3179574abea690a1f39c3850323f6f87376a770ffe3fbc37e1bc1112028f3ddfe82cb6c96d1cacd1d7984908455638014da36486e3b2028a7c34d15f7428a029adf512937ab69ec0bbd5d98549dbf8d59486907c8a1da110bb00d325bb83ffc1c8fcf1",
         Mac => "a205326b6c4959d91bcf22e97ed4b447977e2a3af7e1f7db41e493521ab6a218a868365ecffdda6701ea4dee48e61bf6");
      Test_HMAC_SHA384
        (Key => "c8d18c4707df3ce945f3d7d58d39e73ade087abddac37978c2fd3643a2e04432c9cf8b5f7c4a9be9ec12413c658e5893c76ee2bc3a8e581b1e1d3ef241fef9e0556ee5a7a1e8a332f645b0d6e5283cd82f99392f7df0b28c51f55e983d45757c53f8c2a7dc80facb4dd44c2976cf390ffdd2a69f0bb12fd145cdbfbcfe7d5d11",
         Msg => "09e7dd407526d478b4f6ff64e4cb92bde8cca38bbcd9254605cd193ced0003322d119b4e6be2c635c7e3c470b194ab14fd4514a23920142c3e6a6eb9050606ebbc3b99df19b7ac55efd3c211ff18d2811002f89f42056b199fceafaff3cb0cdddded3ebb27ad6e21534d610e7660f04b4a8cb84b7e8f1256508046e75e57fb52",
         Mac => "cae7cf6fcabf725e2c23915795a8ec62262fb7c7cfeaa93def9079e7dcdd7bfc82eec904312a588c03ee87c43df6f702");
      Test_HMAC_SHA384
        (Key => "8dbb6cdc769851fbe90dce3183cd19e9cdd7893076a6fb7ee0a874d3dff20806bd32fa5a81e5245370ca99c8d5968a38fee966628781450fdbae8733f705b8347159b78ab9e71888a0d1c67916ceedef381f17588ac595d280f1204144bcc09eb318ed92a806f4437e0a9d6ed0dc0bb68361e33b07d9b16fd95a87254d7de7eb",
         Msg => "8dccd462fec7423d3ae5abf8649553170019058b4a8a05d6cc1c456f2fa3db685256b34e99d381518864faa4908144272896ab4420069516326fb8d1db308a5e6928f94554c15dd0d12dab6ea5f0eb55379fec6beae73667a9d04033c443e395facb0f0fd798bd0440c9241b4ceb30e955bc30ca4f35cf0f59c8455f92e7ce57",
         Mac => "5704dc3750e47330ad7dab4910be0cb5f7f74dbe78f5c9a19ad718e71aea72171fa2a5dbdf7cb5579beb97930177474a");
      Test_HMAC_SHA384
        (Key => "25fb23a07e55306e77858cce34f09edf6b49dd8a74548862a0f097cfcc54f16c3699dfad8f79c1c5515600c7527d430b9aade6d371d3a82ebd18a31d8b1d82f5ec85ee0402b549775ad79f7b7c25d9a3c164348a65aef2b9dd7550cb6bc5b7cfefc936ed0091304d3b125234db6fc8708b77b1f7786ed0cba910842093d3fac1",
         Msg => "97710070793d827315be46998cde98ceaa8ac00b1817d6d4d3ded806dc2afacf32553dfefd2d437d0c9c621b8189f78fcbf9fdbad57ade2d7dc188eb4892c47054e0c3f28e36fae6245531c63e1fd612e9b3969553da2fe93ea27f3daf48e156e65bbad4931f4fb74730da212967dc5dea01b421fbfe7110fdc8e5837915fa89",
         Mac => "13706c202ea2e52d614c90dad127e72ee959023d9ac45d1c1266c67b63810d43c44067c36c5417fe8487980b703d8809");
      Test_HMAC_SHA384
        (Key => "e62c2ce5ff8e3d465d344582f2dd566e0d29ddd6205184cbc614563a04f524c3cfa328c7cfb9e9c363a75edde5f056bd2f97189e5ed346a5d60a077186fd64f36d41f3805ceeb324fe9b383a17890839091e44d19c958b37fef51bbd093f39a5c5ecd4372e96651137f619bf0e0e328ba2a7aa9663fe1a2848bbdb4517226b81e18d",
         Msg => "7ac240b4bde64b6b514237f122dd773a6adc2f2d8304a449fa7bf28ee4cefd9b7538a914ce224e4617e6660eced889f65e879ca2f440456b8ed4a149559b3af62cb9335089a0c60083d7f1592df96b822300ddd862c34f8e5dbee0964d12bbc5c8cc4632956a9ddfbf9c3e9be8470626e0cf5c977696acfb8ec0173f743a6850",
         Mac => "984e2dc5dd3274865d0a658e1f6d2eb0854db75e1e02937b");
      Test_HMAC_SHA384
        (Key => "4bb97c7c53368716938c836519e20d6484a7e6a1bc794640e046734280b191080db7bc128d92540d93dd980d6ffa7717a2b1a2e29519e6de8abcb976d2f61392409e7f61dfe87155e08ada6fd61efabc26c87520b818aa52f3324028e92c0115ceb7ecf0af0285f660db7013b7183e5df73587e18f3e39a305ef2fe02d1b06969e4a",
         Msg => "4fe1a8510ab36b97c613d309b5b7ccb243b328e7029d3a88e3efa082acac6098a647376496c02d98ef106d8a46c754f006f4c8e76545cb3b976f4fe241d04cc9305311d44b95d820c6469c8b99d12f76313f87c965585838ab0ce9c58c12208655cfdea9107993b5b27c0912961d84cc2a5d0d94e9200b08898e133475ba0158",
         Mac => "f2722378f02bf8d104b3b50c77d132fa35ac86e4da34f1c8");
      Test_HMAC_SHA384
        (Key => "9f0f91c95ba3c5a4a867b84e5f61a81e4cbf60c433c65cda100c2ebca3e7209a2c251bcb74fdc7640c46f40ad9e73904d18fda94ffa6ef88cd83c30c82df7bc20a89f815f65cfecac36f95d75f8baf79e9e20c81b8fd5beea0f7a2c170e9df0dbfa5f04ee9a7b0fb5448635ff83554a41e20bc3167b5e63611d0918476ed96a3d5e0",
         Msg => "a24f0a863531d225b7cfc907fc7d87b47ea06b61acb68d158496f40a63f80a561c374cca4856461bde42bf3f0456311a24247c5a4173daa08c8416e0329af90a79b806ea0bad674d914e26658403a06e408537925be5480a34d15d87cf13a3d0e05a9eac253d1b02f97d663f278abef8fc4906d1a015bd9da60430c6e16beeef",
         Mac => "fe1f2c8f6af31f96dbef868d461631a7d159d47f6d081eb8");
      Test_HMAC_SHA384
        (Key => "560d76c1bdde2e56ff54567df6713e4e243c1a42f7fe62fd4bb1786a31b68c0defc6bd95482b80b1fd30462593d6591d57c807c1a0910309540d08d3ad1dbf333d9fe30a309ea3dad2c548d8511a1743c3e979f56afd59383716ceda8e98fa8449813247ff9d5e7886fda3beb6a540697085b605dfab2c2ffeb611a85b8e03a81a52",
         Msg => "5a62ff7ac98a6bd1324596741a5554b7193f1eff8e3965ca914926ef29acbf26bf7501cad37686deee63444fd83563780acd4ceb66da036f26fcb645132a96b0f751e5b4543d501d56bd80c30702ec0dc249f1b4eaba24c9db8fe7fa21783a11e93ed4bdb4a77395539b705a0f84967c28fb34e081a071e19949e095bd605451",
         Mac => "5030272dedd382ba3dc06d2eeab9e163a325ed293bd6ea3d");
      Test_HMAC_SHA384
        (Key => "58ab9d7a7d912959917c3416046bce4d8c8c81341a5de1da0c1165b1a435754bb993c461ac57e0199e700888e0393d76ab599b6212e8eac634d3719db6810a2171b67cd967b804d3fcb1352f635503dd56c41aa60ab2747162c52abf633e8a79e8dc6beb96fdbd101307641073064707f397a308ea04a662fcb0392191b61dd885cd",
         Msg => "f83e9f155362ccfd8d228911abf7b5c71d29cfb1fbfa5a528e20863012790c2abafb5a0cf5eaf061f04d0a895ca27f0b71d1e92c335f06c0f4e45e401abf261d22086554e5c655431a620cba1d5c5b56ef3df70a7dcdd6ff2585dc9e7647b7eb374d0814ab60c349144ad8cf768d13509d55407661ac94b829ed4873ae7b873c",
         Mac => "2090dadd774fe71fd9617b2595309e1a024694d295bab147");
      Test_HMAC_SHA384
        (Key => "26bb5e3c7ca428929e0db5d1731c28df597f038500f499197f0fc75aa138df9b80f3e5245664fed58f12250c23eb20c92288b21091b3138f74269d812c96c8d203f0588406e3d551139e3c9232dbf45f281c03f84a348263900a4e57ea9a0159d73c21253329974f503b622a49f48ce993c25d04d581d0defa4243a4844b7278235f",
         Msg => "49a46c7b476b17bef5395f08ec18bb496a188ab2ed944a1a01b60aa1563d2293157e218f74a907e8894eb54b5b20a1a23ff8ce39621dfc1fa2c21cd0a2d006101de66e1a7a9e14faa1133c380ea05eb623ea1edbc3207ef11c8153ccc41ff6ad08e33b6681d2a7bee88edd162a205a4dbff462e238253a5818fc98dfe5b35830",
         Mac => "8d93d5f35311234c1ed500a0baf3a64cbbd20608015ff59a");
      Test_HMAC_SHA384
        (Key => "1a4e62c8a51715ca8cd3c745ac05bff02a48fe5f9fe37d32799eb58d9ed464c852ca8f675a3fc34c6144a12b9c4e9a3faa8af63bbe701b84ff9b0c9d2fd830e28b7d557af3fcf4874bb7b69f2116388090d70bff64a600427eeea22f7bee0324900fbce9b8752fe312d40f8a8485231da5d94694daadb3d6bf3e7f2cc83f67f52829",
         Msg => "4715c0ef816030e7fdf591a65e40ac9dd9eb95673101380ae5543579a81cee5d11e0dd14949a2cfab1167fe86b9b15fbfccd0f97c7d20fab8eb40536e506460ae6cbdfd02793284ce9e79ce292e7e7595e3241e05106fb4e70a957ae30079dfb2f9c6b2822944d630e318d9bbc6e4d4067e2d24ab7e6237cf3fad3ea72651bb9",
         Mac => "965b9108e15614b899c23af2712058eed518965019ed8ae2");
      Test_HMAC_SHA384
        (Key => "c20eedfbffd65f8ed00a0ed925a994627d0a76e5b4669ff61c970de8d01fcbee456c1f80225b040052fada9e57925d79e1e5d4069fb48ab6558482d32fa267ab5565c2f1bfb370604bc652a10c30466fe51d56f957d930889892d661e55e97ed18803e177de789f6e2f7ddaced8c378eb33c668585dd78b30d47725a9b5b44fab945",
         Msg => "ca72a059551913018f1082fffcd93014a277ec636b3894e1cad3dc07a1b24cca639188cc7648d4d4dbe5d77c10fe9f293546e6406f5d94978aed852ae2f28b108359b7ad8fcdd428e0ce351fef03b19af4d1eb3e4f2cd7c427ad79a951e5f02673f2b462694f1ce7e7f12352608f6b4f274182c5d54c654eea3c42eab73482f4",
         Mac => "29d3481d3a4ffc24f5b832cdfe7140058d8488aca2011aaf");
      Test_HMAC_SHA384
        (Key => "4f52b7f2ef19a88156ea68ea5f4053a9e893cf18342bd4e28e35abb92f17f54c6201f073e6c4f6ad94e846cd41f807f0e6218ab2fffcd0a230a74cf32e1ae974ddb84fc2b62562bb6c580c37cff13df3f0cc30ce86d6ef38901f19e73c31e3cb08a15d4527e3f79426624390cfd0fc9a4ebb48d392623a8cf6c69bfe2104ea3b2ae1",
         Msg => "03785732aad68bf0a688c39dd97a8ca6d48a9cf99a3db45ca6b0cb0430d26863add1504195d2610e68e5be77f3382c37d08bbc302ce3abbacc83863b521891f8bd346a2a30fdea55f4274cd5bf1f91b9378922d5b2edb81340ad790aeb3b64d23d88ee1603c0ed6a5134b6dfc69882d5116e1711b4c2a4100818ec9a82a3a69a",
         Mac => "fa89fad64a287027aa65c4389641c7d413566e92fee79be9");
      Test_HMAC_SHA384
        (Key => "39e6d49c3d5d23d2746d15d616bebf3cf720c6e6012a71cae22002f5021a47d0b8636ca3bd201357e132a680fc5dec9b28a9db932d08ae8b3d3a37d7e2ee754b342a69b94fec26b50412289bcf77e6d4095faa545f15a16783d22eae21e18464150174e6db0b837347d440307655d56f0409db307f9773e81cb19282a93c9ca4c3b1",
         Msg => "5d20020a5dd409c7e5344065871e57e01c91a443501dc8bf619890fe231319b5480c3879dee618d319962596539e2970513fb5c0c8eac3a71ff99962779cf1d7e916566d0e29d121c5cec5d7302a18ed00be9316f3de8c669a64c2a960a588f9c8a42690f6867cda7146e8ce27aa6a7fb27606eed9df6a235a42d17ce7162744",
         Mac => "eba38453b3a787ede274e9400435b1a11b4a751bdecd3b22");
      Test_HMAC_SHA384
        (Key => "732b4a0b9be5c5e08cfdf90afe1c800a7a77486c6b9841aa7861584d114ea95548faf0dbe3e541f5af74fada1739f546f4750220a7db945b6697ba1ad38f5117d3e979459dcd45b4116cb7b54c41eb4079969292e94ba21a67d34c96c57f2f7abbffcb91f22638e65bed17e5c5bbcabeafe3e00a5a6ed3b1231cf60b10a5a945a944",
         Msg => "08ba7f516b9cfac0c0f625d111b8031106f91b77098ec09aa9db96203ce9527ac9b9c1cf25d80c355b343a27512ef634a9f093f4e6014d40d016d2a2192c010b40d3f1c4b6cd35a740d75e8f9cc7c20d67d77c5d3e41b498240c212a2325cb8736b1161a67a2fc7e35889af138aaee060856df9a5a757d086c628ba1a4fd3b56",
         Mac => "2bbb7e600e9ad59bd4dd2b47714309ed53f0f55e1741ea8c");
      Test_HMAC_SHA384
        (Key => "a36eed3e91b717f21d56aa25036a5e7ddd74bb3296002fcd21885e306b95b9d78e27525d4757ee42aa3b5ceb140a06ea6280c6806084fb608409dbb6dd320b6846b96d9cdf91397abeca4f33e1b6cb42674adaf200c6cd20a3996c427f7e8da833ece50241ad1d23c0cc280452b5d50c5698a08e5f0ece94e4ffb9db39c3681ebd87",
         Msg => "fdab2a03a7a1b55fe050da9d5f661f7df63c07c3685b89dd7c40c1c54f5ce629ee5f7cca24b6ca2291528f49fcacf119eb06b69170f3b677451990411b369d36306122d12093ca66fd655307a11b87a943e26e834956c2b75d47a334c3bd8cdbea3986e1413e9b744b108ea1f6bcc975295897629c8c93e5ec526166eff99b60",
         Mac => "4b5571d4f15c3896ac39caed4d7aed73fa6ba7fe84afa961");
      Test_HMAC_SHA384
        (Key => "eebb4ed3f628aefddf7ad08a9679aca962dd6de66bbd17447c4a6d8c08bd12e46b8eeea373e7d3641f58615aa6cc27e3bbbc0a5f10a2eb4219b1846812c393a943933bae832ca702fba1f06c2cff417d348039654c01900b96b6fe5c161d58e2fd30fd992edf70fffbbd466b2ffa439f5291c0a028c24fc67bc3a20f1ab3a9b822cf",
         Msg => "f186cc9a3877e2de21e274f0cf6a67b5e72f2b6df5a33d2e0b99f191ab9f6eabe68efa3fc65f7831ea402e3e70e7cceb1827aabba5c152a5877c3ec5b878e352e4bfeed0cc1dcd87ec3271335bc552fdf45bb4aab3082913618658d57484fc49314030b71358e9c670dec4375aaa02d3c4f4d0a2e522cc5ee2dec627a76cc378",
         Mac => "95a4986acb7cda7e95775adf7ed7388e0c7b54bef073e5f3");
      Test_HMAC_SHA384
        (Key => "350ed4bcc51bb92c5fcc6435688ae8ae2afc9f9c657eca4b06cf799e3609aba396d7b56ac9e2e818348c6e3701e175506aca90bc348459b779515cb6ab6e30fbd644e76625e2a98ea8ab9b10544c05274cf2b57d5fb99e41d167c57a5e5a5e9b7cbf3157e10543b64591b36969b4e25b58dad688ec04e11295787d9156b67bab10af",
         Msg => "4433ee59b964f1cd20212245d5e95162c6837a3b78f1ecf84ba0aa9dfee11223759dbccdba43a5b943068db673469d55624b4d43e13985d5b94002e53414fcdddf9d06118def35529f7c84bf838877df7bdeffeda0c29e732626cb1be12198c1089c92cc3a4fe9bfbeecd10b0f99272898a458e3bc727ffa19b9cde60eef2ef8",
         Mac => "b53f7ae9e9c677897739b85a8188d35c6db029703b6b5153");
      Test_HMAC_SHA384
        (Key => "7464290c01b494fdd96cecb8a07110f04dadd5758010fb5815d46050f906745c3c42edaa68bebcb812893fb9ae15b83aa8f4fe05b0df724555fc35ecd561985233d4d41e8bd4fc6aa3de2f22c2e912adc5337dd06f3f75cf011e5bd50aef629581a2473211013c5cb4f025bd83f30693cdf2bc9e6639ec3c41c33ad341b8bb6f4d34",
         Msg => "25dd3a089ae04bc7cc3e97eb85e6647847a45c3a3e45280974fb414c440303bc1184046b38bba3044255e4545f1c7b0910d626ba236a4028e44594c492fc6f711033f98addbdc4274605a69cdaacc4431f73f07c835c35f1950caf1f7574a01289b0c16f722fd6b83f1585cce0dd68addd43618648612eedf0183d65d7b1c127",
         Mac => "e0f9223c3fb6ddbf6da7e51b5d7ce9368cab016c4cb34a9b");
      Test_HMAC_SHA384
        (Key => "f3ac4422cc724378100d7515ddfbf3fe340002b7976c43acd69c2acf26c3b18173eb4eb6f73622540c6a73dd3eac5c4ea58cc34772428c6bc7370c0accc8c1feff4640d2cb416e2a5d06f35eb366ec69f5b9e0020923f6086216652318182ba93ec702be701a90c0abe9dee261b00b16cd9042318596e9494e401b62333d594ad975",
         Msg => "04a3c1e89eebe7b99ed3bcdaa3cafed8956ee8da93acbfde2d29a845d4e1bc928e0f5e6fef4cccf144faf51c11e38baabe1e58088d33d5a2cf7ef96058d94f7030754b478b09dee2fb2f4852e50a2e77322dec0c46b82ce336c4b87235028c8f509e30785c6a44162c385c8307870fc958634beda886eb2ccac38c8455a59c76",
         Mac => "07f73d066eee1780fe9488ca2f024ed56600920f6e0c728640d1f6b53b24002c");
      Test_HMAC_SHA384
        (Key => "6f67acc56e8929e491df252d3c8d497a6fe7a662f6d691bbdf7db15d311c5629db340c4aebec71bb00b343090227bd5b103524afba829d66710a41033b087330ac15710211932a7dee4c505bab57ad098a3cbaf3dc576e01758254615deee088c85203734848fd3342f373a89fe6c18dc34191b4c31dad93d22b1100fd9745391933",
         Msg => "4f34c874a909e1a3ec1869236116995baaafba7b02bc8b54c6bce76e3582a354742bb633d4539ca35889fcc572ff888e0e862462d1ba4be5a37aaf0e6b9c207d19deaf0eea1f13aee7cf4c6db0a486d5778e3f7a4feeacd3a703594811a4118c4935fd2d72d40f6aa2d3a244a16b5ad8eeae52eb03be76c7da3d2d46b0043c2c",
         Mac => "0cd3c2f7ae6353ec7d70ce932f3980cbafb77159b2fb7a5c85a1cbc3a566ba86");
      Test_HMAC_SHA384
        (Key => "6d82e6fb6ac5ad3b3121ca955176ec0c91ffb3d1358416117cd102126d68437ed373a8ff87fc620bed60ae02c101b476143caec9919b4cfe054b57c91fd096e874f7eeb6c50cccfe854ec80d96a0820b5481d08bd43e1c606d6607b2787f525255f7ff4baf5eb3ba00d25fdf57ba1f7359b7633c85d74ce0bd0c59f702dd4263805c",
         Msg => "95be84de7f82fb79f493b3c7e378300f094836d76558dca8ec16e2117f3544ee1a0b0feb4e377443f1861bce1418ba3a35bee598b6a7281b8e3c531d3f481563085ccca25b729c4291d0be61dd2f1b1b7e1d1a0939a0b607071cd33b0b76d253c67a630d8e7a9afd3c38468b26077e3b4d2c7c31d78aaff4bf7f0b72cb09a444",
         Mac => "6ce9ac951ad8b75b3c76fc7e82b498258a58544cb4ee50bd5c96138f37b1fc33");
      Test_HMAC_SHA384
        (Key => "54e6051ab2d16e9654e96a1d91fd16a49c3c7377a0fa1a200fb12b8a37468766168e3fce6f114c281d0e804ea8bfbcec16dd642903671089f4a08411e957e3ad316a1fd0828db45a494896be3f3f67643db6ee4c5154c5f51127517d2fe9f7094e828d6714cd0ff2819f94b67f0680d5bacefa2ab14aa12b0e517a1432862d4215dc",
         Msg => "6250c2a87119c8b62794baf18496af65722d0b349d25f53984d10cead1085583e56d7861b8f32dabe0a1f138ef93fdad024278e69705ec989fd7f734d55a430e4d1cb7be5019efc66782ea76b6bd030d8bad2321373334411df5d9d8085e5c54c2e6e888e293f84fe5bf0f73801daacd35f772ad25b9b77c25b31a9f131b899f",
         Mac => "9ca65056dd811103ff8b38efc557d9759e0b7ee19c7ed557aebf3b6fa9a438df");
      Test_HMAC_SHA384
        (Key => "13ba5f52beddcbce4a797694eb05caf10463ee0490b8482ac07c41bae5cd48f391091932f99b3f689e15d7cc2d8098cda3ef104bb45b30066eaa0b571a11db1e639c45fbba0bdec1f8e0ed2745b673c139d4682f42024895469cce4b89e4ffd5d09c6b15c7d5b0bfa0023f0efd5063b5103a7f19005797bd8f7711fdfbefbd002131",
         Msg => "7f471a900ee49f2cfa1d3eb37c951d810c349364d4cc3b5b64fc479da75517dd16bc0bcd2b0f95e1190c9255ba6eda71c958150c51f7d14f6564d2bb12c7a96d92c289a1c20d5576d75dfdf14c8b0b431ef2794f3c19c667399249564521c4a45b213c15bc2408739bda298d1a34d98075c866357d78412b494e527728ab8f09",
         Mac => "a7d699dc5cd3405ff692db8a910db64e2e2504f6a3da92a65830a748bd89c2fd");
      Test_HMAC_SHA384
        (Key => "c8608386aa689fd9fadc56b98ccec4e2fdfa050cf3fa9dbfa6b91769a02aedaec13aa8ff8503486e8a42e6c04c0b98c433bb95e4d12f9afa64338c65a33d5e5bb75c3580876bcab8388a103af4cf18e7eb3831d998e4533e4683be67d20cde1cb2ae72333608ed610e9c1c4f0d810af02d592113d28391345392f698b6fd3599bb17",
         Msg => "267aa69989d062695016065f0282791ccf578a7f231e27107b33cf9f78844928319697facec9261853dc47e0b9b3e3ea435869330f410c7becd12ceb6b2011fb39ffdf93ab37c6709b127aca731de334872b15c3a89d8272f5e16ec5f539a4ade3be68ac49a4ac39d1bf87665746e2c042d8757715bcf2bf416d7f753e566a06",
         Mac => "bc0c2deda203839165de872fc54df9300e31957e115483a57c0d370f3404213b");
      Test_HMAC_SHA384
        (Key => "783f153f2dcf9a582c3776ca094984112081a2a4d93813ce2b1b22b95fdc08cc172710368ed8f9cb216b9c100fb3cf917dcf887bbd5b4666cfe3ac73289d6f97b357733616ae31f436815cc8fda5c4525bda7a6e8afe35099781f4331e19e57655b786664bb90a7a7261fe1a5c862cf9c289c0a5ca8ba95d89dd4222c7b83210032f",
         Msg => "5495d82b4e44351ab1cec03a485e4a2d00c2ba49a81cf7ebf5db090dc9ea7b1bb4270303bc17658c59d894e8c4571a8c71c3bb3fda4155717fe10bcf2bd0a21478d02b2295e6e351475257072ec4cc894acddd10be946620d3caa1153fe08fffa8779aaf64187812832552be0f0f26cb92ca6ae4d97ef29df88013078e800983",
         Mac => "9deb737429c7b52b6a51489022a77bf3bafe73876d38c45b749cc65a725ef577");
      Test_HMAC_SHA384
        (Key => "dcf32810f1efc1db0e5f6555ae9c954b729518bd74ceedf7d9a984fda5e52e2cd364d11fa631e0d03ac18aff5e7932d8a67120d0bb7876d0f65865952d5ba057cd0d11a82944cca0125e4137a8cab5f26fcaf3c2a6763e29d4058b9ea348ed33f177517525306b93bfbdf0c3349606e2f826f95adcd22f499a385ee0aeb4fc096829",
         Msg => "f2c0a5bc165710222a9053d9c9a193fcf69487f7be553a3c190a0c3712a2fa8327b1205ef37b7c5a0a4ef55625169cad7f2b31ad7e6de94b96936e146bc028673557bbe26911d11a964d198f8ca790dfc4cbff39fc8cc4152230d622730e0480e45c7d30c14295c99432c66c487cf5f98e1df78380d8540284894b4874b51637",
         Mac => "17c459163a9d421bf7dfd4bb1577fb856760f789039ac84859df13526d84c55a");
      Test_HMAC_SHA384
        (Key => "8b7cec45eec9e4000eaf9ed1e496f1fd2d93b0e1638c3636eb9d429390bb063330977af9b5c5f6b1471e0099c1636320612381edc3dee923106a2ce47396ed14cc0e385fa97e157d72fa5cb4e39eca9fbf71552fc38fbdefd988648c8f035f94c7a7cd7eb03b67ebf50b592b348e5103b147d5ad4ce9d921b0be9193ce49843d8a2b",
         Msg => "24c631edf1b1bca7ed767d72a73c9144485494996cbf141830f046738cd2f88fe40dc7e5d986922865242f2727da5cf6fbe2f848ce467320b1a583a92b341861d403937d1f82328a7843cf508f01cbfbf3e2457de2f98f2e600fe2b586a3502c1d2ffb7f6bad85154d5ac7b386bac69d57dce2fe50df518965b5cc6144278836",
         Mac => "a26e75b00f59658aaea24d3b0f283e280e820afbdab1f255e00cbc8a284648c0");
      Test_HMAC_SHA384
        (Key => "332d0227fd1f7a1282f8f5d5df338d7218958570ac6d7e3a6c1beec28ccfcf69fb939423f08c61d6c67c7b04098cfeaad149ce684eeccfe1a5de5965fa7be6cece170ea78c3eb6945e4084ed45ed96ad699e738bae75416687e539e60f74596156bf58fbf8bfdf12f54cf6d9bcdfbd42899c5c22f1903c90bc37788df2418eeb3895",
         Msg => "e8bdd28c63fd43e497ee0aff3296e63384173ed4e084ada746f3be9940d3f4b10a800e44f51588680d8265aafade2c0424fe31091b46156335bf907f796a6e87bbd4d89109ebd516461011a5156ddcd8f9897588ba19893d0a1af7e8681cd6d545e1b9db652631d689c194574becfd9949e194b785a7101d0c2b7a3cd6923383",
         Mac => "e5437da742ffcc8fdd58dc08b68d23d766be75c3ff93a21d98b048b6d116a70f");
      Test_HMAC_SHA384
        (Key => "e199ddb8612936d2e46b4e301a1e772b0312d5a903e713f9381754fe0b376d900579511fe576cc99ef2a758e8640de93fd900de4abe7304d3d068c4a50edb76d405907003a8b4aec994bb7d96f2d259761137bbcb9f3688fb6da5425263196ca3740e7a38bf016918ad5fe57fc6bb600d7a0077b559323894a9c93d9b58c72709536",
         Msg => "10af1c219f304fb2b6cf06124a3e7d9c16d8f3aae1d9096303ca6cd42640b3434ac68bbf0c1811fc27927f5e3be70b54cd160ce78f9a5f93e2e109559a001d0501a5e1e61e4d2c7c37b7129d9498c3cb8690b1c1a85df14c654fe45cbafb165b3d3466bd5f3768d9ee2607f7deb86faa482e2a60b389883793fa45120f9a66ed",
         Mac => "7395adbb0c4efa1e2bcdbfc55407ecc628a78e36a32085bc897f28a9d8e61e03");
      Test_HMAC_SHA384
        (Key => "c3d9b6761ea20f88ce1662c1cf561c699022c96f9af1d71673409debc22a9cfab33904419d7c7a65e3d918a418a5b50b667267e930284783f658740979cc5bc9206335a39b1cd0bdc6709378d0e5bda29ce0eded67bae79fac17958c44734c41d2fe51835eaa9cf84082db23403dba96fb13626289cf3fd35c26075a6b47f8cb90b3",
         Msg => "d7859c229eb0d77abb3015c9fa2d2c959981e0ab076dbf6ceb8a49686802542e9fffaf617664060f98bc053fbe6fc0c92c3c536b7ee3c518a42233932ce32a3dbfb4542cef77577c305bfaea230b8a9e1b257c49daed53709b43c40856d218423f8bd3a88f52936988f63af1b3674fbd6d23a26ea1f22f1cd7d345ec6e36e8e5",
         Mac => "bffb2babaafc27251a4451f262dd3cdd8d9d79b9a6fb3ca613b3ab6da1ac719b");
      Test_HMAC_SHA384
        (Key => "c1ca87f626ca3716770d0fec1aee4ecaf2558afee02f51eb891b115f5a663520ca3a91c8df1200d3f4714bf7b9d44db47be5552ba6f1cc33889c18aa57d4bf097603d03bf4897fb056690fad9642f5e66b823a4ecbd6212eaee50a74163d964e4c8d0cf86c16fbd3235c21b6b8218c884993ff0f58c59703865cae679d8b0019d441",
         Msg => "182cd2ae62596fad1c4695ad0af75253c9e73aaebe3700784c0b47984a32b5ecb4054946a091efb474f852055714f288e55e7617270e4354c2844d336ee72db9aa0c7503af994089a26a0da40d33cd4e90673a29d4596bc4c1a2a519f1c2755a640afbed75b989b50c656d93169c0a2c32cc2eedad609f4db12cf752b90bb257",
         Mac => "8abd962b73c97b9566d08fa5c96a51c7c53843ebd12069d0066075e0980d17ce");
      Test_HMAC_SHA384
        (Key => "455b64da72b1100896812d4b3d78c162bde6efb7691fc7e20921636f87772fe1eb5d88f68924892d79d8218648216989ed673589ff39ea2a25f08f21cd8f263b21ee3ca13618bf5a87f11011a31c5919221b21aeddb81d7e5fa44968965f3883ce57a862e1545a96a7132175b431381a434cd8ad6d640ae59f87bbca4aad0ec0dce1",
         Msg => "e7f20812443092e998e1b61788e95d2c70ffeb49faf97587f04a2f964ec923a59cb429827af413037da228a439cbd4719f709d278ad1599694ec9e492e407b69f0d665df2d8274b9cb67d0cf51b966a642c7df94aa38d225f69438be080721808b62a66f84631fd42a3696e0f83b7b91000a98da82b548febd4de43d05a77fb2",
         Mac => "54ef0088c120d11add7ebefb1dffdbb6ad31ef6556215a1625c641e91955ba51");
      Test_HMAC_SHA384
        (Key => "e402c12a30cca01deb1f5826828bc8f4f5d72d2776464fb5321af88d6f57aa7bd7c9914c1348b7329c3b776ace5b341b3fba4b824e03454cff0352430668f32d21c9f6f1abe7a7fc6f3345e3ba90b34ab4597004efa6c97c41cb4d53cf22824a6b0bd6632030d8430a0ea8db6bb1ac47fcbe85f681b7420ca07bd304f30cc09a5c95",
         Msg => "9b8bb10d82b6d109bacb9cc75d8c9e39e696cb0d963907281787ec5060abc728d87de362be530b30c8194afb0aa4f5581a43eb3872971c5e15a54817762a0925952e14fc6bdcbc318891b82ffb33252c72c4cf5ba237ac63e982a91132f4a9491ac9cb4351fcecf4425c6ec9f6e2379b3542fce0efc0bf1edb4596a65eb2af7e",
         Mac => "c4ce885753645790fab556c3e1ddacaccdde386ab7bc39283d4c84d3798df5b8");
      Test_HMAC_SHA384
        (Key => "e486316b3ac5ec100f43c0eabdbc0a32b3b9bb6580580a332d4f6698d02faf495ee6a551c188a1fc2a4f83f4a9e0ebaafbcfacf7a3667d043ca2f2670d7fab8ede75cc610a43ac23d6ebd29901fe1d6f9c1942d71cb07c73ae0a7e75ca8dad050b3c8ce33e7e774db9219523ee9e08493f9f664d14be6d492b90f20b30e21b748e42",
         Msg => "7a04f851d50cd135256ef044ed740ab59e964565b040edbef0d568de1cf36cf5adf96feff4c65f5468c4946c3f2603a63b6db43ac731760e421ed1d79b3d3c801e7490cf8d51bd467303bb47b5a9c47c6ad0c176ec3602942fd43127521c89d374804339c93351d2ed334f1e7887b7ffd2c5545f49d8f919600072176a1abbb8",
         Mac => "24ed011518825f9d39d06a2523271521dc7949d154d6cb378be20ecc2281b2ceacd349a61a2806b2");
      Test_HMAC_SHA384
        (Key => "0ac01a0605adf7c608264ebd667c38790e36363ebd6b0d937270d40023b44b17aee76eb112624a7adfc310b0ebd7682747be0791714984fccba7679c4c4184cb76e2874e881bcfdaf4e680d61389d36318bdb19a4310811457883eb04d89cc904af88c65cfa12eed2fd6c6ba47592234697d5be19987abe4fc5a7ec48d54cc6f1273",
         Msg => "ff5611cc449662ecf2a04287a828ec0400ee6c4b15364ad84278680d2c582dcd02d8e34603cd5e0e4190df72a5f5380b3481309290d728f4c274ffa9369c344207944a427e12712fd5f262e9402a8b3a2e006cadcb7b41a4ca17e1a563bce6f597f10e68bb4ee177342f949380b02eb976d5e947ce08db0ee3c9d5a8b8a18c0b",
         Mac => "b96936dac473277b4f7f632730dd16a8fbba0de0acc0213cc44efe4af6f381af6c0fe5be563e7072");
      Test_HMAC_SHA384
        (Key => "c08eb5bbaa85ea0b2de93ae86fd6a26afd30c1c112db3d12172f638266a60d9053d8c9a76daa37f301c2b375e03e345262a57471ab1d52442ddf74e66ee930670cf2ad64fea345da1c042e3be2355ac2715e9b04d6e80bc98feeab194bee4a9af2c5a919e5dadc668799f365fc23da6231437ea51ca5314645425043851f23d00d37",
         Msg => "66db82e65ff854365c79a601fecd3cc75318bc674dd5c0e673c02a6cd7f3b88f484fd8d4c81dbd7341f5b25b73dfae7631b9292ecdd92f30d1f3b370ef3c256d3bcf47b698503cad70d0e18ba9f161a4d44b04eda70e48bbade833cd3c29e78da8257793b6d9f96b53d2dd98864b7dd8a496f4aac3bd340e7068538ca5012677",
         Mac => "a6b6958979e726d66ed908188648e77b0b35b76011800199e40eeddd0d44f28a981aea8d2c335852");
      Test_HMAC_SHA384
        (Key => "b8fd9f9a77243dc528bac1a968794afedefb594cc02e7a01980227c14864e9fd4b70c0c73fe2c5e4a0ce0e23d792d2ee7308cd1fb600e61553ed100676de6e9605b0baa92582e776016a05dec76666fbf296fffbcfa8102f3a93085fa988a3616d2555e934edeba3d1f5707f40df4d4de40cb589140e4078d65cd674ea4acf830b38",
         Msg => "0ea8885268bb33e52d2ae60a4398c81c28db6c302a5aa59ed6b99cbdb2b91fed2f593cdbd9420f00d161d86b7dd650c17e0d3e82e22a458d9bab00e7304851b8b31ef596f30d5c06f25fb8409aaa5533abf728c9f823aa6cd386e7c9c6d3d1d4843fdb0c1ee6c3007a6aaf1202dd7c7b99e1538fd30d7d42659378ecda204a49",
         Mac => "97ea6505694b21ee748dc9eefbc753161812642b6574b9a66301a4d54e0ea090a2c1a487c244b7af");
      Test_HMAC_SHA384
        (Key => "a32c359a9fe350c9cf5efbb393d0afba534c432cb92abcc51dac667541e224643fca0434bfbc16866d057fbfabd3c90c82517da3df12f44cfcb36a201cbc54917bc8f3ab85e62a9a463e8d6b22f8ba17c659ecbd5e2fcd2f08708cb0891e30fc406d2c895828330d41514d4060082be305adb7019e49f0752b2af5acf2ce5fac7403",
         Msg => "3215f9112d9e2d511dfad07ba78bd5876fb3209e8a8295dc35917554c72dea54e4b8e0ebf44d17a9d3a376a6ca34a3c5bf9ed03aa849d84a464a8a520f87440b6c1cc50c24fe3c9118dea47a32515497982dd2222536e98d19fafb7f0ff9981930094e7da7f9c39154750200c5291382622ace5ee791f02d18696fe0b0cb0b04",
         Mac => "540ad3fa372fddece3b61e3e0d7d9531c92a4418327dc0b152be8eeb38bfc92b2166bb10b243f8a3");
      Test_HMAC_SHA384
        (Key => "ce499f38ce5b7da7a4b0349faa0e07a26f9b12ad07e43b60a624665e6ec4e8f7841e3e0569860013888b10c50b7a1774f324321868e1e86b4dd5604b1872d060e13e3900b8d7524f3c34c1ab6a2d9147b23ee1155088d9ead918e3dd146c17f00c33f6f263555ca3e933b01a6d305e64d470876e68e0f724727657db0abaa3ec2e85",
         Msg => "9e3d2da55720996355c025b8acf42140dd47b70ffa922ce80bd163afaf2fa321076399c3cf3fa118ce86411771fff6dcb3c7349e3feba8e1d936c0edfa486d7ebae828bdf39c336fa476216d93309854377c567dd4957230e81ae414c61c48ea8176df7b0b5cd7cf9e37cca05bb08e0e320b259501b7123b0023d80e5cd3bbcd",
         Mac => "435b5499b7f3e8e347d1d087134441b3b56fca7feb80befbf6476d1657fcde324991d526b5b4ddde");
      Test_HMAC_SHA384
        (Key => "c5ff2dfdb19d7022bd4263e6dde7a8b3ddf3a0b93dbadd933e43d6283d4edfd0409558b9cf53248805035d43e66a456ef3d78074fcaa81493613434e8d1c39753bea87a59a3f7260364415a32786560d9e3e1944bdd5b495aca7a2dae9087ba1df84238abb6b42f17b8ef5cd4743c4d805afd3f128445cbec8885c95f8188d9d54ed",
         Msg => "43ba51cefe257a4fc630774174db94d14fe6e0df8a44d60d0ecd3d167a334d62683713d7f31c17f1765c3b15959be62282d9624a79eb83208d2c8af1a7704858cc39870d9e2ea5fe26c882a1d04f9d88b705793623a1463150febd5872154c77f529731909416e9d5edb148c2cdfff2a77d2ed4b914c6668e0ac9ff2e10a9fe6",
         Mac => "319a7bc1867beaee22b2f8f2b6ec132247d2b81020fee310816049816c34c717f651267cd9070cee");
      Test_HMAC_SHA384
        (Key => "34972b6645a47e3d87c5a568693c2c4f7de0dea57f12e4f892f33186ccd51d53f5ef4f788c54e1be0b26bf6b6d06505cecd059540f851e94e489caac8a0f1090f3d113eee80483bf4e8b091da76be654dc7fd73b396d3bc5b9d877d384d79a4cb6a63d70629cae69d75d4d232151355ed3551f0204b084b2984802a3c11601afc4d7",
         Msg => "0e072f73a09fc1ede5f39444b25b302ef1e6fad4399f6034a20e57c3d70107576c8cc445724e41c649f600a0b6060d0235d7ecaf91ddd05eb12d0e61b53cd08642ea0e3b19bfbaf5ef743bd279b51d7dc6250752d1a3edc257cc86f9e6c001bf3729f49cbd7a95407e752c2122f0c86649d8310422761f273af1a9d3911500cb",
         Mac => "3896072563c0c2865483af821f0546fb21cc1604eff53bc81b77cc975ccc53e3a696be832660b324");
      Test_HMAC_SHA384
        (Key => "b7622c1d4bea038b6b8d5331f7bb992ae59b34ec2e5a6932e8c4aa3aaf1118314a0146ec8c2b40d87791cc34a879ef7def78b32a3dd0289ac3fca94b5888604c1b260df55aff02d5b34772ec7914ec1a5a7023d83eacf02671f89ac4053154a572fa07a1800e526a67d5d0c1343599ea6eaa0b5dfa99cabe3ce1050f7fb4fb2597a5",
         Msg => "9c359eb6a7991e6f11dc19764e6cd05eb51a61158ed986c36cc27ff5bd5c4dfb9f1b218ef52614b7ba5d18ec969b2f7baf38db2cc2d3d521724e0102e019a2577bb4cb351a6f161d48759721de081348d80e6e3461cd630230f3787217d93048d90882f23dfd8a6a60297f5e4f3ce58fd5a30377924f982e4db9ca8e8c235f96",
         Mac => "5d7af8c97f7d6550b5d4f3dfbec8c50a43e583f762631f3020d9a9c9c0d6f3a152af83eac5353860");
      Test_HMAC_SHA384
        (Key => "b35dcf54a3cc008dddb7bd1c1b764f388c12e95c90fd899abc011f322577f163dbb93e81b3da21484a94b97046818781df8e17e99faee34c65cb741bb002ca681a0ffef92306269b304579b8d4a6b42c4df9bc5552b184690cdd310d625a7c23794758e37bbad52d98b1451d4b4c9de1df391ec7316f349ab71f9e2fc1e7cf3bff4a",
         Msg => "870f1b7e6c4dde00cad1bc6ac28603a2341db17d33b08983b7a566f292d6d006a6eecd785416f94438d2d9b013256d8a08fc04b10cca54d7986fca84a05e1f5ec9ff2ca9d752ff0a64d62e90d8a96bf495f0592072799fef6b9f3a34976e17fd5a08e119db4718d7b8a46311f958276943c158d34e068f5499fe5d095d4ee06a",
         Mac => "938bba0d6845a29865e47b56b965b2bc52040859e9ba9c85d92ea0186663c98a7bb1fa2102637344");
      Test_HMAC_SHA384
        (Key => "0ca6d30a1ee6f05d64998cab5a57b1600c0e64023799e267ab952926f370ba4b38c29e4f63e1a74782b0f85b6db7c77aa979624c8c017068a2bf7ac85092aa79b726d297db80af7905d7702966a67217fcff4e0eba221566e34eda7cb7d7715f517977ccd0ec925db5b8fafd8c4b399fcf492f30072358c934eb522a6f679964ce64",
         Msg => "b617e6965eec432dcc4684bb749ed016df232b884600a52c5fddd19b77a879c8c1959029ee636818fde2267855b2729b114d73639b47faa87cd5fdda728d48e8c36c6f60d21d07d7f078158b744ac7470e54628758967cddaecd6b93403afd9265a56a8233a286334c133b3cfaee37e27f40e23ba67293939ecb030e0837028f",
         Mac => "d266505b5ef935dd8013ca6ee3229c96ea6f571aedfbfa33e915ccd5953de0469331ea1128f6d973");
      Test_HMAC_SHA384
        (Key => "137c94037fe2a15b39aba093350eb9c181eb1de36f5f4719f695821156dfabc2fb05385da4dd7980c41b1ead286bfafcdbbd060c47e0a93f9c5336277658b73bba49e9cfc02f8743b891cb7a468a338d701e81c1bace05b78f6a1ee3e327ff3f17f2af411d03530adcb4b0e0d694ecde08b794ea1151e4e89783422de7750b37dba5",
         Msg => "ec16489822821c1407092268101d992f7fcaea78343b226bc680a430d28e200c9387bfcdb33ca06961f188e2a460d56cef00b4d2f5869416beacdb58fb32d7f89723f7ff8e5a3bbb0244e9aa8ce8829ad024f40d543911e2928a40324ba072791f7258f65be3d454128dad896fbd86ff49be11f1f85b8019679f3c886bdfdad5",
         Mac => "84cd11c51881c491f78034348a4250485f1b56c81092da410fa0658b05b5d3e715ddbaaa08feb6a5");
      Test_HMAC_SHA384
        (Key => "6933fed3a66bcd401155d22f84725361139c998aec52f34b8150fd5fea622119847b5f0edf014a0fd76c535a000f4a10483522ead770f5283a2e47cbc18d8f042571f4ec6ed35475145c8aa16532f1f2261224217d9f08130ff90d086592b016943d45d61d88f35d124c006d7a824eedf7582697a68535f147d9d47e9e188d351808",
         Msg => "6f85955d51fd0e8a3b261b0fec9783e1938c27b12be5f1140b7207e0b96d44d90048e88d42aa8e7c0fb45f7cf588865c9a0ce3c809eb046c4add515d352986b48768677c368bafce021f493a4dd0c2692c2cff01beaa2bc9bdebf40e523ff7452e6b78f1d6aa57c73ef13f109a7721507175e125f32a4f718c2358bbb9b97ed3",
         Mac => "1e2c9fe55d17da4ba342480eb2d30e1ed4fc94baccb9194905dcf0350ca6b0eb5202366d646a10a9");
      Test_HMAC_SHA384
        (Key => "9e75186da77aea91a67a3510458694ac908d0ae4562e8d6bd2cbc5d88adf119f7891cb406889cdbea1023353c720636200844bad561feac85d4312ce15006c5211adbc98d9c566058ef532d5cc724c0cd4908fafeb910233fdbaa33686ad646db3f274dec4d7bf4fb47ab8fe1c24569255d85c52dc2cde95fb580179a68d02d8a488",
         Msg => "ec94d16bdb3ead89ab8ebca0e0cabcc1503a651d7d2f5426224548f10ce490df2b0dc47ce953b4a7ba279ef4f559a44ee2dc7ce114ca6a37f9a76ba0afeab3d819b95ae433f5533da2769d309098bd85b6f66b5fba758c63bc85601c2ca3fd9ede22fc6a602c72928b04221e588df0adf5109960183aa2f394648e2d2a18547b",
         Mac => "ffd507856b7da1d6d2ab4870003fef27669c2e06df3e628fd0b871b99b71663fad824f677bf2f2ac");
      Test_HMAC_SHA384
        (Key => "b06e828d07796de7eb344a656dfa57624d19fabbc086a42870cffcccc5503a0a63aad09bf47150dd27258a6ef864f4fa335d5051338888bdf095dd9239a240063db000435058a6bbecba1ebcf6b717444360ab165bad430d7d73b5b1e390b00846685aafa596372843db4d76ef5a86e787085532bf5e9cc11f51ce504b8351b787bb",
         Msg => "3df4fe4187f59bcb01814904c90b4585288a37a721c163e84ac42390dbb8959405da91ba85c3defe78eaa534716a25f0c905a9a33669b7069fb38bbc2f32c433a96d5ccbfb67dd3a1521d22ffb617c3519b2c7dad8ac7c116e75b8d6fa889d10d0b547bb116902468030ba3a9078b31dc2987a962d111bd25e13942563438af5",
         Mac => "b322e829a7644f36f5ce147a9bf3271ec2578f474a465ba01fc0ce928954ed391e50e7727a0001d2");
      Test_HMAC_SHA384
        (Key => "74f41a6b1c4e5713499557d6f7e889f8a8ce2e444e8261fe6a8e5518769bdfa88188349a19b9f3a26db26675b3e40539c8c63b3a16286ddebbc539dbe817fba7866f9631204471cefdcbbf768cc9043006a6d4cb4ec2decf1c0c2ab35ad09f50ced0c896fa97d87e400aeb3f4a408ec5a993825fbcf7bdb8d48bb208956ed28ba0d4",
         Msg => "9a121482c7775a8b5fdaf1c2fb7de1a86ef931b1a88cf23ddbb47fc9dcfd0267cb173a6bf62b7c68fb6ff85b2df93e2539d1013f0a491aa9e991cf23e98656a082cb95f87c1b2cdd0eddb51048f94ad4aeeb48a426165321145a9b4ec3e85dff0755ac8f20ee71d2e24cb14a13280e9e15709147c499a68da23868b232cc1f6d",
         Mac => "b0da90c043493511d94f22fac35b5962749c49972fb43571b8478764dffc1c25e3a7523fd405338a048d38dd1b75511d");
      Test_HMAC_SHA384
        (Key => "d87fb6ba27215e5cb65c3b5b34ac2a32037f30e1f7ea603d5a9bff8a330fe74bc70529596132f6334f36c0952dcf9c4c664ceb48f74539f3768a65c1535902085fd4fe138ab18172f1341893185a139773582c5e2c4369e4201143d12bc0074ba5d57d0f2c08c8c0a43e8d7e7db757bb34893a4a1d4db7b95f18e0e140adbcbba3f0",
         Msg => "9e1a5d9f236ef93f2cda60489166c82dce322327046644cc406b42e3005c2177f3b7af2a0159adcc8ba92f2cf413462e60b8db1ebb63de44febfa1b9adc87e79a480c0b814e3c17ac91c4f5eaef954ba929db6ed2c757df15d6d3430b66391993adb58f265f57c706d9d8785c7023df9ed497c3c5f8267fbe7dbc4f12213a100",
         Mac => "3c7cee960221c9d9f7464aeb70d198bd60414dc3ffbfa7a2227a3a375ebb8f6448e524706e1e3ae95541bdcef2b31d9f");
      Test_HMAC_SHA384
        (Key => "4710d3a0a835d5913a96ad54499f2a5329a95150251ff1a6b8e07ed200e51b336f24f90ec4b4e0d539310ba9fe62391de719013d625b66cfabc1abd8431e69629e62de7d1bbf88843a0af2a10a63cf93e01845af4ec78b2553c3b685d0b9d0823b942bf5979df425a4e70b4553ea123e7c6ec5afd3ab893219ae47e28ffe7a1ab080",
         Msg => "c6cbf0916dce3ee4fdc3ade93875b2d3d6cb5ff627e52d7ff967f863bc154b95e4a1de7c8fc05da468836bb4cbe5e7a02aa16e1faf462160228ca8f80ee977201f604f1dcf9a08ff41378f8e6d662b827eb304f27821e50f1e79411213e174733fb04c5c7481c85d52871f61682004e19bac2957cc9f02f6b5d5cb981426ccf8",
         Mac => "b3b489532bd5b701e3fb7da0601ce9c94536dc3d8acafafe835c503b0be50a0e852b551456a328e65c76892f448912f6");
      Test_HMAC_SHA384
        (Key => "2cb6e84fd408571c65af8e26743fed236cc3593383ecd41eec6f51dd4ea8c65d7683827f499cc163fca57ee68709886956ced8d542c022dbc1ccaa8159aa59da5bbf1014cd413cb9a89cab2e44149e8010ac1f5f8647946b5e0e95af0211fb6b433139174a3df0a4d15bbd0593aa56ee0025d5dc36cb53552dfdb9713127d39996a2",
         Msg => "12f2890cdbd85863ce570fe3a418431bbbcd74deb16f3fa232cad6260e3cae588fba777509135172b2793d9bb43dd17a81da31fa67353acc6423000a3b2c7b1ac78f7dd69085e7e99cca1d7c885ab713d7787ab189f58643efafd03bbf58d37c6479837697b68392335397d045f75cae63b0374d40388bcf7d772f03c1481f44",
         Mac => "4c32a80183ca3f1b5d07d91924fec55cd3c8e0a3719beaaaf3b7824aad1c1ef49608d5ba7a4aa5b53c244e896fec2fc8");
      Test_HMAC_SHA384
        (Key => "1a8e273181755e05df15946114db513993803b32c4dd9610a700076dbb7f9db11e0c113ef54a4deb0ee02cb4c4cb81b023f85a434d1286941c99544109349e524d48066c46c980471b501162a36ed6f6834147289744bd82946b32a4eb704837f0678d233b99fe024e8fcad4796d58f4fb828a4b6a1c44c355a128fe27dba4494e94",
         Msg => "35ae3481efd30d5d668dc0e147e6ff837d30a5465199f8ead6ff2b5f8405288023668cfeeb89f29ae9567498a4496f7001c487c664aaeb9c1829dac7f1d7679f2f0179fba63f155d1c4ce069f315df9c0810823adacfe188efd5453c73a8ea3223280360691eff0cc8180b3c7b75d86f59bc9e8afc32611522ab73a753a03a9f",
         Mac => "432f310947c3ef1f146401824f451025f4c24be8b4c92587a5c4263457924f426ceb8aecb533e4788d20fac0b25856b9");
      Test_HMAC_SHA384
        (Key => "c4b6e18a87558d2ce6a5946c65a9446f66cda139a76506c60d560f56a013b508d6ccbbaa14e24ad0729dd823bf214efcc59e6932cdc860306687c84a63efb551237223641554940a7a60fa7e6ddad64a21b4a2176b046dc480b6c5b5ff7ed96e3211df609195b4028756c22479ba278105771493870372abe24dcc407daa69878b12",
         Msg => "37b4cf3789e40a62aebde9cd9cab34eb846dc10d057644e39f94693f6acf201d089438e1d81330df6ce54a203ef2e0639e92fb63eff2225813ba70c024ecea5f650f0f85788eb08fd15b01b06ad7f1f2b8f6b777df9ead05225162c29d0cea3b366f79abd11d317bc366370589240c9dbbe21bd23b448ef1b2a366cb3df7cbb8",
         Mac => "b3abb0141f7a5b4c39a1e5e6ef8bb64456200d42d15402be97bc516497adbe241cea596fc9493e91c84b9cb601eaa38c");
      Test_HMAC_SHA384
        (Key => "9147253adc883da2d831a57b55e742aceaf10ae4db91088b4095a6f864292be46cef831e39523f818f17dc24763448d0e0e6a2b78dfe41622c7bf9ecc35e996e50bab8bab10bb24cc1c8ed7dc43c61fa05915775bd2e709a3743ea4532a11ff287d04e750b5b9eebb76f60f006a495129f1bb08634c99d1aaa12016b7a9ac4585758",
         Msg => "fed888f3b12b8f17d450b4303279ad29d90f8ed71ba7ed89d83244e1007396e253b756496bc08421fd0219925c12a5fa3e5b373fc3137d63b36d2c580710a216acc9cbec837c4113ac61b789046c971cec0deac54d1a7938d90a31b99363cc319175ae8100490d166ad555be3471cbba6b8f7014c0a62833d06f1baca9545c5b",
         Mac => "380f48d74b2a6b7ab206cfee0a4c0fa5dde0fae81fd0240b3da352070611cfd45dd389f9e6b5570c8c202d4178cfef9c");
      Test_HMAC_SHA384
        (Key => "da03db48559d2e361cdcf29eff209d75339c291ba45709848c76619745be76d35c556438e6c80f6517525bfe105ca050f940583850521b408021ce0cb6fa17f5f0ae13f357954cc0ced3e53acbda180a6531e383af73fdcc459a0f42247d2118bf9852404f0ccd8f6ae6f81cd7a4efe9a1f630c56ac1987002698e0138507e85f09a",
         Msg => "62c1d149567f05a0b76c4fd32d1f365d170cb165cfb38f922f1716225472eb36a127327007f8f5c08479ca7beac4b0aee26f3bb130bbf1ff390ef344c2a4e0b8fa81f6acbbaa7a620d945a22ecdd128a4b3acc2658b1cb41020809fab87d1f9a74b76624f9fd5c2e59a649f0b9d0229b5855adeccefbe60092eba26abf657283",
         Mac => "35931980eb488506fbf05def3f501c90cd99e8d18a48999b4f9b1e95060d3a509050ac8a7a8461a9fb011f2fe6815a4e");
      Test_HMAC_SHA384
        (Key => "290660f114130cb1c66fe88b2d9a87969502a765d86f0989ce9e80580b2c47edcab79770243f799886d2da6d6168dd53230c7544673c325d68935b9cbca53ee83f2bc4514d60489a34aaa9f4e87d9e0df97c4a49c3e2114fe521a9c8f4c9746370aa0d1df63d21bfb84080a82ba173ccff9d51fd54294d6a2b9192651a5f9269457e",
         Msg => "beace90b45258d290fa0d56c359ec61505083be3562ad93418ff466e2faf969d8256065e4e07edfbc111efd7c480740d18e75854a45de5260dc6fe2188549cadec4d7fdf0c0e1d9d4350df0350aa8c06645705577a3a348ae71f3f78324401e22518ba5724420557bee50bb88222f74914dfaab680c7afabcd92713cd687ab85",
         Mac => "3ba6d5beb3b97d29c93887bffac37cdcfa407cb7ee9730dc0551144048dc83e4a2d24224f02fecdded21bc805cac3418");
      Test_HMAC_SHA384
        (Key => "033f79314407bcd35919d1ef3725fdc000540ef085c5faae0a3dc301491a9d5cb98953720ff9e74b05d079985b5c69441c0cc04b23e0cccfdd1e0b6951474bbd5d490e5142f6339f63b5d36849776a4cebed37982cf9e55fa6626acca6cb30b677e67275e4e5eaf4f831a908085f4600f4603a7ea9f78b85ea70a8d25190947090c8",
         Msg => "893a7f54d8739af07d5ba0e1e4b911353130ccdee25bd663af1c57d6b530e506d40705f556d3ef8dd1e0928e4e23d8cbaa152b963dc23879ba1cf3275696dbb12dee7ffde14a417584875afcb8ce1e26146881a8cad3db0d8715e8ab9b5013d65a97f453c200170f5efaff1169e16aae37d0d7fcd1b74689e0ad3f4ccc8715db",
         Mac => "7f0c42b9e080b844295fe9de114539436aa92d184b6a3cfcec1de8a84ccee0f38f5d16e34f955ad20d6a20b45ecf99a5");
      Test_HMAC_SHA384
        (Key => "2a452560cb1f964b927daac63b72342755a94806ad044dfa0a8252a41a66a6efad96a2952141cae61dc415c583cf88f39fc30990a55f73de5a9ce64911d561a4d92b92b6f528ecf58ca3fb91a2e3f4b4470791090ea41b7bc1b1c83f53a0481416ce9bc92e1d250046df043382f7a1f4b43a8579d21c6f57a888a38eca0f84c6cd45",
         Msg => "ad3d83020142b3f1f07a3d02f602146749c9c3925efd0b4eafc3ce08bc2b2c6d4f63eb3b052b1c500a88fb0824bd18c5f377b4cf77486e5fd2561ff64f5502f3a4b218657411ca1e18fad1099fcf53bd13024e51fe843a722d81eab4b44ab4263393d12957de0682a33784ad70220e7432d259c1fe9bb8b149aaf9e9f3f4892d",
         Mac => "21a02fc0c319e6d7fda5a5a0eadd1a7505a7901dc5a24b91792d2f5952982b20cea4b55fac302a5d4c99700992b8a7d7");
      Test_HMAC_SHA384
        (Key => "fd545d84fbc11f642910e828bfe7d548e422641d227586a11753f6776d0fc82b0c4245ba8d6cf655f2deff6295d7afc45fed545c3aae54cfc988798a56e68d040c9c27436685c4a2e76a19d10c26a81d7f0892f28d79ac9edadfd45753c18680652baa286c54b0d46f7edf7e0a1eeaddab3dc5e7021eb695b221afe64de7db267fb7",
         Msg => "21a9873b258290a981be2548cbb026097df680b29a96f68c954d225c6e23b6951e4308cc350ace6cc25e25ab7341d9bdfda5e047be822716a127921143ce3e6c5472091f3fe554970d1d07ab86ced6d19a3fc3920056e43b1df467d62789d3588adf901c8b3aaa902ba3d22f4e81a6af1c69327ba837b663cf5ea992647cffc1",
         Mac => "78bd2b27a34ebec53c0c15732a23dfea9030a6e63eaf4a9f1263c7a933b6beaa4d3b647e801e61d0c44bc9afcc021f2c");
      Test_HMAC_SHA384
        (Key => "225374e44a65dd0fd9cfa2f7bd90572f4b7a17ba92357528e988b502cbd43d68e5e146f96cddd7f3b4a2f49bff3813e0939bcf3b0fbee0d9fecf4bfcadbdd69f3af8bf59ee78ad83cc00e79d6aa4c4ee0089636bbfec9bda646535370c6d59574a1f47cb773b48074970e3c4a7db53a2bccb39124bc78f7342d2dd7b91edafd93cde",
         Msg => "267d99cdc5989ff8d200f39665437b4d9ad862e42b6056a8442bf40e92fe80999e13dafe5962ad87f71feab501847529a6d01ec45390d20e831d12d4d766a51669ef8a205e1a31f6baa6ebf578759eb8db92bd39ff727738b37a2fe18bc22da930199379fb49920ec29cdda0f29e5ec1de252989578faef07d4b327bd49b801b",
         Mac => "984f82f1b69bf49cdba99b702b205fd50a7f618b6732a48639fcc37d0f5b868b30b53411b5167fe7f09b34d5d73d2d1d");
      Test_HMAC_SHA384
        (Key => "552e518ddc1a518c2c853897083b7ae8136273f6354ff1ed409ef35cd481b02e8058dbdc298226e1b073056dcf07b45d44167b6b324931a2c42cff16138466d14ae28310087892b0052cb2e3f9ebe727b9406579a3250cc53d192fa21972993cfcf5d2913ea49ee174d7c75f4d8e1c2dba06ba87528a8a3ff48c0b69aef45257ddb8",
         Msg => "6f55443fe65938a33f0749655bc60f4c3ca62b0622f38763f30ae0c1e06b82c846105357d2fd13bde919e22d473c036ce689dfcd21fe4d5f1949106558dda106b446304676b9e535bcf06b661c35afa38abce5df7c35cd6c4ca2346fdd66bd90819fe1f61ab635728035ebfa23d89c5af2e645267bc18ff353bc53c6b82e5dcd",
         Mac => "a9cfee8005eb9dfba8a2f919a0a19925b1f8d349a9cd9fd8ff0feddcef9fe687c5213aa77c1a05a72ce51909c240b746");
      Test_HMAC_SHA384
        (Key => "3609e874c69e9f3516387502f9eb82acd029be530936ae7be6dd43628062ff920bb759b25bf263a1a7ffaac68e925da15760b2a67d8f864c6b6b4461845a07a06612038570092160822de9a903d6a59329f9c3e3749e7c037c94b352ed6320bfd082ad960cca20992c2bfb53629ea0a9cc5ab9b2f74bd7c9a2c059e0c4649017d06f",
         Msg => "eefc0676e9fb74262e727ffc07135b6ceb05e6ed48938a4d802665473170a757baeb3ccdfb82ac215c8d3f86100364c19beb533c9114f256a106f5fed3384a800e84b49eddd7b6e3722db234ecbd52a8d570279aef9890fc30dfdeed0b7db58ef1afb51218645a157b39212f22a7edc8a37ba82ee9872de43498663e61a8b12a",
         Mac => "33a941a00df494796c3ca14caaa71a7e95479a60b9d0274cd1f58a0e809168bcf1e6e5c47753237d4b777fc4cca86920");
      Test_HMAC_SHA384
        (Key => "dd908ec058f137a44d76c004821a4750357615820de32e5d51df25f258b2356941518efee482ed4a07416fc4d662a7878d79ee5678f7fadd1d95b339b8f641bbe7876ae9a7ab1bc67f154454fb74e9565c56775a8e4654f75a38b954dd28c4e939fdc98a8ab3eaa11cb9e7bbdb9837460ad65798381a62347090e249b18fe57c9d7a54e775e4816245f7ff015c16b6deff",
         Msg => "b9377d9bddf40ce17628b4570aced9e4b132e655d4a535af35752fc32f1cb40440b8bd96c4bb3fa703e453026e6e95e12687c903be03c5ff42528bd878afb5d1659b1683138a9e2c92dc7e4a3d0e8d693e32ea39559ce3e3d5df169deff8d67d32c8d18a53c8ef192af87d57fe188a22021b911d1fd95903f4041a3b1c5de1ad",
         Mac => "435e4ac37f873152151ba089e7f3925ccf3746df525b41cc");
      Test_HMAC_SHA384
        (Key => "7438c5424ae95acb1a77f27fcb4338edfc777fb0339a039e37617242bac8ab8d3b62c5c82bed53cd4f2ae67765ecd4570a6e38a8dbe93a85db66915a15d146998250baae2cd3ea3494ebf26951dfd0dffbfd6b75472ed48673cdcb60e5b985f80fa9acdc95c0a868b2621d3dd845b4ef96cb1ffebf8f5708c93d283c73a8f012aa16a439aede13d171366fdb404609eea4",
         Msg => "dc6430d14e675dec5976e671af07b9a453a38d6e5b97c9b0f5eda2d7a89a84b1dcf9b47f9d78334b9c92e57b76fdf2a739246da825d734f1af411723cc1b3cdb6b20c1ce43c1a419d019e0d29823d9e3b32bfa188a829d76df762bcf0e81849392c1a1e9caa878fefdf51f9d9de33501c8a07ee71400cde78c732703f6352581",
         Mac => "4f9c9ab506d2b2137defee277fe205c88ceb16a6eb63fa9b");
      Test_HMAC_SHA384
        (Key => "9e49b49d15016f006dba47b8ca55a161e9e95151581e6b1de7d6555f5a1321b760151a10c9c29d25f34b2b43850dbb5060b5550cd3a8dc970ea22c34da9c654c87f485b625c83d35f7a2fd42245b520cb03971beab5b1400a85784c07121f732f92f1d1592daf6396008e63e0e080b9ebfbdceee48ffb8609c3e888d87688271a00d09b779c2703718c30ebeabdc900d77",
         Msg => "6a90ace01b9a7edf02747f6de85756a34c551d4aa890c0a8f6aaa69a737c94e3a30bcec495b77fcd68b65af20ec182e1500da793127d7221d91624da8ab37a9275fad33c918e94bc0986ccf6f81f142b71adba85c3d81ef0fb045b2caa112a20e845047298868754eecd1ba12fd7d528b81e9c4842078abd645d94b959fe6e36",
         Mac => "1cfad85f7f5b21fba6a15483251ff307621f8f92549e88ea");
      Test_HMAC_SHA384
        (Key => "22715d8208870414fde08df9129caddfc68cfbd879dfff1523fe8cf045b450302092aa892692bb63aefac0ddeb839f101fbbbf980ca81d51abae9d5e21b29e70ef80d044696a4a6e6932d756442b9180fd9ab210b962a68d73e165e5f115ffb1f70378bbba59d7bd97527a6c05daacb5c9f37a476957c251e25e8c8d9d239d7da0e24af502a58bd9a120502817d91839e9",
         Msg => "66580cc5cd10686af49429771a7f96ead165fdaaf8ff47c8ea88cf04f56675930e0dee1fc2215e1070da280ab6ad04b6292953c6491fb033b405c8c9999c6be670d1e37fe8e1846321c184c41cbd0df3705f916b3e925e11660772bafbd890eef56c93ec269a03ed7011e6ad34f7d8280dd05ea1bfa278e96a5675de04620b32",
         Mac => "447949dd67cf2cfb6a090c696cac55dd79d628308d04df88");
      Test_HMAC_SHA384
        (Key => "e107f34583d99654ad98e215b8c99952199f73f5e26ec01b8c634e69f3738da3a291f17a512498a6acb82d3556f30c232ecba62ad1f727db60a357ee8368bed7ad7b0c9aa225b8df3773e649592e8e04510ddb9d462ad11704b3333bfce2a42f8b2f0c4a7fc43d27d731d7f8ca61681d0bccd8f64cef05f501f9aaf766c885d4c313b934eee971a5125ac6ebb074e397e3",
         Msg => "ff95d63521f4aa2744e30fa310ff7e4d6927aa1e393063b570dabaee490366b6ce1b661e9ed8e8aeee2b6afbce721f7badef949920799305df71484e10f8a2b2c95ffc35d0dffdf0a58bbcacc28228af2169a8d6ff19fee4e094711ad33e2b08f74ae0a23e72b09671eb4fdd74986390cc7e2dfe5e786cfb792b7e7b173dc95f",
         Mac => "9c4ea79f8c3c19ac173cab5a10931d480a3f3b7f5e121b1c");
      Test_HMAC_SHA384
        (Key => "d489d4235459afe93b34a99d7f8b7cdbd788b9c66ff41805e0570c0c5f619b9d34886d8e6ff323ccd697eaa021a04f316a12554bdfb0c45eba1dc5ca7341ac5933ee150d8dc3321d6951633a407d07168f2593278507e1a9ffdecae2b7cdf6a9b801f329169385e3dbab3df244eb4d932e0b9be4cbc014ec99e343dc95cf2294ac0b30697229c32616eda05096b2c9af2f",
         Msg => "6f81a80f78d2b33478c737bdd7f60197e34ae39a1f03aab0defe4f3a113772af5e8c038672c4435797cfeb3d894faa7e8558d56ea4745b9067ebf7ff9341a90c3fff66292bb70f065342a0f9c44caaa3af1303d1bc6bbba0a00653e5f2f22acb3a6338be4cb3fe88d4a7bdba31f4e74e8701d38a0fefb428b2d7ccb3d752dd34",
         Mac => "15fab21a2cb56c230237260a57e9edf573225c86282ede7c");
      Test_HMAC_SHA384
        (Key => "4d40943fbc79937f7cf628df461783d87f45b74171271e1fdc19f9beadda58010d843af69dc2f4ad003dd74b9b570d5a981cc46331758fbf2b9f08aaa0dcbb9902693fce5dafa629dcbd18418ff6bab36b07d4ba931d3400d654cdb47872a4dd35d5edee83aa709a186032e9ac5c528c00ef316e1f85d58be31f9005bc03dc74adb18a7e971a1ca9ba0d6f6c79f29d8c5d",
         Msg => "61d72517dc2c10d953d91acd7c86d68ca4210e09fedeb5ba3b7c1df95acb6ba9c26b471c8ed6d83428a0efc919fe824b1f865da9803514719fb63c38cde1da3c61831c480b5d47d8656ff17ecb7670846db392d3a2ee8f1380bb3b14a9fc806d67a70c63fcc9470c33cb88b43bf4887fb53017500c100dea0511845597214484",
         Mac => "e947661a5621e499fda0fbe1a823c4a5cda8e3f71b541f8c");
      Test_HMAC_SHA384
        (Key => "afa4b912e9adbceded28f67dc34dce5a3a02a730dafb6c081a266cc9d34669fef5ddebd97950da7896464c6838519c68aed0bc6fa214ccf04fc1eb5cee774de971b28d9274ef455e7111dde63302a0118d9d15234bcc8cf669edf786837bfbb48dea4743c4d22527e4504eff9caa03e03f315954bc6cd5a2d07238507a989ce7b04cc0f65041a15959cd4abb5b8fec5a2c",
         Msg => "d73376199cbf8036d6a075ca00afe0061847bbca0aee846b6d3894b46de9ad2a085ad2947e1e5bbb02e4486fb69fd6cad6e550b9339528b7e4bd46dc38bba017efa20bb8a9df50319e1c831d90649081fe8817529bc27a38fe9934929b046cbaf2d2c98a0649891f110ecddc764537b2f7f8b79f28bda275239305dd7e0e389b",
         Mac => "7e4524628629714cb10759f724b8e1ea910276b926feec54");
      Test_HMAC_SHA384
        (Key => "a05bd170c0b3e42802ed73fe3a610d938e6538a9d05c623f0bf01afd5b9b80d3026cfadeb908298b44ef1cfe4900c3b56240a66871d7d634345b24f91951920153f107e22d2a47a59ee621271e8febc0b9d22b2362a3978589814002f0fb0a3cba735f45c52224bf395cec4161156cfdbaa530a04ac88c7a33e9d4df88a0cfcd5f796ace28f7aa203dd8e414ba9b30b48e",
         Msg => "d19c7a8ff3ce59d2cc9c231d34d085366210a28aa7be632b5d1c0e151ab41bb529f743ac3a24d9d0586b5d731c534fe920594144b7d93062db32142a6726b612877fc2e46cf81dc3445a786969e626b2d8f32a5ee6d895122e0c0fa1ce8cb38ad37d20c2f113ccb378b19c848352b29b722787609b8139443df22603b5afb925",
         Mac => "cfc2c7263683f3c8bcbbaa46efcf0ae1f41fa16e5fdee84f");
      Test_HMAC_SHA384
        (Key => "84371c9ff40b745ab5300bc914512c1468f98b339704e204db54dd9ac6c534d88462163f61d9ce058a2ca16718aaf5404a1eb9d912460003d486ef636adeda0e6b1aaa56ad4882e3086fa2055d7e8b48d7836349711d9cc9b934d100d3e7f033c0c69e89e142d71bb661d54aecb734559791532bbc73fd7d12c5491809c9be720cd0bb8203ae16d51d6b04dfcc3b398f11",
         Msg => "007b9519c21b4497e5176156adf75bd32cd00962fe23f62a3702fc719a74141a0c1b6c6b4814ba14d31fd16d330071005c2564476b88c6b796d7a5fd63d3ca8719f6d546745890b29dd37d0f5965b1ef81d7e5f9b29ccbe845fc9ed78272fdbb1052f931b0ae6d7a2c7b8ec389f0c2aa842fb6ff3d27aac72db910875d1956bf",
         Mac => "23391185157dc83f6f4c9b3337882eee11dbc64607d18f34");
      Test_HMAC_SHA384
        (Key => "b3edc0ade4b88144d315331bccebadf891c5e05dadd5c4ad053a938fb07e36970863fc2401df9284ba65305f52661052fd1824da57760874f888360248e479719475a499627b836402d312336679ed7d344b08b9180fa07f5fb871eac2e52a407fab1ed5af943c2cd3e74160b02a2cc25de6f2c49aaa74166352ae0ec589314df18dd3a08f33a524542a25aed783b569a0",
         Msg => "3744c090cad18c19a41b5fcc4d2091ab8920b70e224e80f5e7ccdd9df5d66551353ef7832618a11bddb6c00f4ad76934bc1b0854a7ba4780a67632a7bcce9868df75b425b7020c59a3e99a2bfdaa2a439f4803dca5fdc91a752ca29efd9798593cd23f9d04f8977afe9c3347ee029b7f388ff0cfa47fce6c5ed676aa41992dcb",
         Mac => "a2854198f88bb729acb19da0f6ffdef962d7fc6d904fc704");
      Test_HMAC_SHA384
        (Key => "df0251af61d9f87520a8a464bbe6004c4c9026afe3cbb58134cb242c8cf356d70a3e6ee80bdde4c7e622d9e5da9ca7fe4484bd9b1557aada84c5777100ca3af1691be8487fc36b8a9b0ef4f19da6932225fc05b106e9cde8f79686c48c997741656068d7a6d3b445a635a08dec4beb4057c1a6fb9cc94632f605f82c18a7344f67d7959e6655e880715f83c3afd5d8e042",
         Msg => "4d5f76f718ffd84ce27d09fd4d0359a1de1807115c72c0d8790b63e4b57707827e743f899cc39dd4cc3674f6ab0be22ad6780e895087af802424ce804b74ccf7cf69a68031947856093a400feca9e58792cc781a38feb916441cdd6f28de8eb5886734449f1a73bbdfb0f4afd78769a05a3dcb2bde7ee682221a181a145b56a3",
         Mac => "d1423a9148699c8bda93c8fcf09d6e6ffd0c8f6436ebba7c");
      Test_HMAC_SHA384
        (Key => "cad62de2048c1b274cae09a6311e9b8900852ad18a00aea62716e1ebfbeea11678be963f248716769d00455adacf81e8b3fffd90a4afab8ece0760773e7133127205266a194408211b0a9907d9bef0ebb6cc1ab2d65504a626259a109ce53108c091228c6b2db8d0ceb44dd5b752af3d10d2c95ea85a7f953756d9dc9cb2649f684cd5cca0a9f02abfe7a8ebfbf28884c9",
         Msg => "31068b9f6924197893ccf4b0d2a10129cbc4ad2709a479bca018b58411ab8b936e3640acbfb5b7b3a35337653bc76d4743e3b5dc826a951b65238a20e72b0822b38fbca58d1a14f1ee6c01c2ee4cfc4167404733585a757187542c986be02a01483986f49cfe3818ba40dc2eb5dab3ff7f00eb93521b20a44fd42252666ff919",
         Mac => "c2475ba7fd88e8207f78679b7eede8d1294fcaae6c705c86");
      Test_HMAC_SHA384
        (Key => "610482010c09a931cd0eff41a9974af03086334f008fefd38aed1fa91953f5491026994e72e9cb85a8f9c9447f7a73fd7191ad1225d305eb39fe96473ee72bcf04b4a8f1184ba6eb8c0b5e26f6b9c8c6bbbd047f8e8ef8aa336b3b98894c3126c71878910618838c00ac8590173c91749972ff3d42a61137029ad74501684f75e1b8d1d74336aa908c44082ae9eb162e90",
         Msg => "0ac4075ab986937b4550272f2020d50b14e6dd247ae87e8aac650c12bd7843596740db05443e5c4e41fe34be51fa07345ebb462f8541034982a5040269fd16bf9880a313e9eb873c2c2320f1d41ba45bf0f8b8615d733e283a7f6eda9d2c28a784cc880a0f54bc4eec051250124b5586b2e55a406a46d62ebd3b7223c0cf2218",
         Mac => "ffaa7de925467d40a8a8ec9a006758eb888c08ae910863d8");
      Test_HMAC_SHA384
        (Key => "295692c6db3d276528169b52c458d2f44cbcf5e0ccac14f284f8109decccb87ff5df323992ec9d7d7766f4692068351316ebc3656e3b092b92ac616a448834f3df4d6239e015e460a656b09676cbdca6c2b207caab38f5c1c4327922190d98f07008eb6ecea045353d4c9683cd6b0fd6d97b87ba8b8b1edfa2f3206e73422c9d2e78958263760824c5b26fd82d2f16cbe2",
         Msg => "751009ee3c0c5f512d314bbd9b145e903c20a6af308bd41f3f889acf63bf57b886faf6288c21135b9468604c7bc748caa2abd2cef2ebc70c1dfd17c8266a79eb237f52564245d8760ab47719e3247480d904d0b59dce6f1fcc3a795374b3012dd507e4206462f4ca167d56cbda1329d86795680b391e127dd6a98817568236a5",
         Mac => "db1b1d1978f71cd6774d0c87a731383fdc74c29222911207");
      Test_HMAC_SHA384
        (Key => "7eae9b4df81fe3e13aa5b291149a892835c3a937fbd584b88a3771f11c0aa39b98675c4465e75ef28069a309cc0f4d6eaa8ae0edca98afd841ca94f1db8be48ab25ea2ebff67f3f4312dd2043c9e0519345450381a16e80ff6a22ad925a98d82f51cd60b6fa68b31747aa9490c4e996ffaa761df945818a3d1459c6fa46d87c988285e6c5cac0cef72d68fa2e328f2b925",
         Msg => "2ae09db7a59a2ffe199f37e4af4b2d51bb6c3b17d901f1d63b423a1d41e08fd14a8d6ad3cbbffedd9eb125ad9cab9a666d8468339f65a22df6cf557f03e0bbc7f8d2b1c0bbc46b1f39bd67bafdee9fef01370344c4ed264b9cdb38c94e863416dcb65ac79e31e08b94cae553fb9aa6b61e8ef4936f22e6f8d66bcb42495b6286",
         Mac => "ba84b3d221ac589863b78760bf6b9839d476cf8d6bf14faa9329b30a61831407");
      Test_HMAC_SHA384
        (Key => "760c1da063e104fa69d2676a8673dc458cde629824a98dbb1215e329bb88858ee43e1222bc3bc8361d84ec0c0f8e6cec8ef7c4748d741e303a0bbd6b84829b44da175104367138ae5bd7ced85ba05bba5bead4859a8ffff6b055d82a146534b4e1ffa4edda6b9c8bab33d475728fefd67d215b7055e27834fc5dfc0f741b9606805ed185af123cf49500c88c5c4571697c",
         Msg => "42145074b26d8840327fdde4979ce4f630a48eef9e879fd5e6056117c5b899b94455bab08b2f5990fafce16476dc88dd019781b08e26733913762b64df688ecd2e1cd126fb6fecda15c24bef75fec731cfd4d68d674afebb26739020ed7d92f229f2fd9da8372965ab59854d3c088b38c1e4f34fd2f827a24884f81296008f6e",
         Mac => "24b4b0ca2348c219c151297f220b2d19def3bc0d8d6771748145d6eb1efe5a5f");
      Test_HMAC_SHA384
        (Key => "55d1a4864299e24bb53181794b5992ee301651062aab4e23d9c5ca8d3df6647d7864f574d5c3b8d10a80aea3ba3f40bc3e882707a5bd891bf950640fc4323090d38fc0323ab86a04996167679d0c7c20c9c5daab761044d218206f7fc449aecfefb8cf6779623f0bea3a756dfba78e425835359ba48bc673bd9db384422226605349e8bc98a7810f8574a15cdcf8be4b73",
         Msg => "846573a89bf96dd9eaa5db7799453bd92f8d7efa4df05e7c9cc1f2ed0499804a1ff892c1ed2f4cbbc97dfc1a9b78f3bf50ae9450878daa388d80ffef8c5b2a7bfff9a83769232ed347b43e9c43fbf9fdaa613446204ccdad93433f936d5275080eb0dc90799fbc274d94c884f898f49b27ee866580f670e39451dd610f460af8",
         Mac => "18733c84f9c0258beeb6b5d426e408ff69fa7b915b2a33ee43f08ef27f8bce96");
      Test_HMAC_SHA384
        (Key => "6a2584a7acc2ba137771c3f90450d20f3c7827e38685857ddd53e54025056c12bf4c9bbd5be6c6940d64c759a431f35e37d04deb0065fae06d77f59b75f4041c2975eb678bc4df2aa29c3da0ceaf7cb55aed616b5004717c9123ac41240478d2cf29dc6fe466ee1f5e9f8f962cd3555ccd59c92c1d6ad39b6fe072fadb3db07cdaefd69c10d3dcb968f7230366a4679bb9",
         Msg => "2eaa2265498645181a92e52f375b67445bfe8dec5f46fff465152bea57054fdf904ed46cd8ebdef396f82127415ff6cf18b3aec7135c264719f59b6773f2c0e381860e1cabc45c609b04af6ba988532e975f2bcf7f8a45f0095eb134e12994ff6918787eab58e6e8917c3703581fa7e942caab0c8b1885789f1715588af2f2bc",
         Mac => "cce77edb3896dbb2dc8eb9c3c21dca293b31e89ca5ac70054ab58c14b4eef28d");
      Test_HMAC_SHA384
        (Key => "24a262e7bcff1c84c390b9028baf3831393f00b175922cfc668a26a6ddff77e4d061dd4c0b9f9edb22471d3caaeeab47a8d29fc94abea983d52e6375dfb4295cbe9a2b7940c9c0949de9fe41a9ca87624e03a5ed3ad99aefd56231d176ea99dad69573f6c5462ab61bc08397f20b7587121a3aa5adaaa6494d6db8440a686f690099de4c00de83498612d5c8eb791cc0dc",
         Msg => "4c1723a365c8567dc52126be2ea791bfa321d7137c582b69b91cafb497879f8a6186ccca89944d82f7c97110a114f8875cc58254f14e4721744a09f9d1be47ada89fb4775b95e7de65ff54d9ed377b379a175f3eaabc3a933e896f5af86fc09dc86cc1f203528c58b6cab763399883990721561bcc2a6c88c0e2c91e34237222",
         Mac => "b8e4d0e1ef33e45d46c11baf98be472d688ed629e3ad98a229df5881a944af8a");
      Test_HMAC_SHA384
        (Key => "5425c3a3074116f7626c227450b6444e40a380cb7930755cae11900dd33d81202facebf5b15f602e87a28c10ed8eb02b43d1533d63b23454314f823374294ff7e4e343fa83478df8318a1f707bd11b4db5f388c648814a834c0451015a8510379b53317a2500879e88ad445ea3876cfdbd92892ed1a6a13228b765402d59ab297e821e3c3f923467b39261a00db98b8383",
         Msg => "5e1e09f59a1e2c5f1e8a3f697b40f1108d3f9b5ffd17db87099e7e3288e5a415286a1ec4fb8f1bcb324b04fa2820a400a24d8c3c5544b6cfa85e68f6bcce5b97a9d41d190b33b479bee4849ae50c73dd312c4af260975eee032a719d8537d31969c2cc9bd3f03f924abc87f2bceca5cfc2439d2a26f91d0ba36860d0eb0852c4",
         Mac => "502c8f03f0e293a35dd557fed9de8c4674b1209c8b5cf4002fe76046c654f039");
      Test_HMAC_SHA384
        (Key => "f04cee99d3a813c1d47381422d14d8cf14f99e65e02b83806e26e98ec3e7a3a4f246fd704086fd6f872be95fd80b09f864a8aed79dbd74bb9817c3f3b6a69c1783d492f7de1516d15bc0f8c7e51d2b8fa8bfc96d2e14565ec73a49962f14c82d6b9eb416f47de55017dbb7609c71c5fea6e5f40fda57b4d3c33782607559b14f714b6bb5c9e6f35585232c1344305fac27",
         Msg => "d4b531125de389a12f34832f539e0b88b95c41db22407cb23c498f270f784c5599e0470eb5fdddcc424674e980050312bd67d6f932cf8b4a287061e15f1bb23aaf55bd28f0ada9ca184dc7bba3ce188a38510f6a89cb972a7ba05867877436005f3d1bcad59df785f970050f82a14fd870417496efdaa93a7d00fe224f2ae390",
         Mac => "572afac574fb3e28920fa83a792864cfb55d18546e6cb4c4214652cc2797fc4d");
      Test_HMAC_SHA384
        (Key => "e04aaae39bff1b1d82c59b6883602ccd4c58882d0faa089082bdc4b92b97fcfeda51b75677c8a9b4fd965a93c74185d20bb1bec3a4e8587f14ed867cc909c0619f366918a7d5ae25279fb137e1dee7fd98ddbe3bd19d841dd7c984cb01ec723d37e20951b38df21b05c9e87c5aa11af6fdc3d0be1e315213d33a06cf5ca9d83cab3cde2824573c3ca1fa4689b9f1e56442",
         Msg => "292a2ff749c5acd4ef56adfa4827e0a9a5173c4dce9cf2a59904a024bb00c898dd628209f3266de4c9afeb59de548e01761bcdc4ebc4fcfa440a7bd008252ded55932b562c18ba8f0f047b04ceb4e2a79e5be9d96b03068e6fce5aac04822bb5b64494a69da47b1feadac4c3bf4fc4e24460f956f75ef8aa43d9a682551eab36",
         Mac => "136467c874c375f53ac1dd50424c06cf8235c78b61df5e3dce91127b271b66b8");
      Test_HMAC_SHA384
        (Key => "62e0b401b2054a6d1df230f0340b0c2577df0235bafd314bcd0980485b0f9ab71316370306f99ee750726727fb78867e20cb85d74fcd11c03193b81b6c3cf116c7815d5e8f8e4c90391083f148903d5e72ff6f86fe92505670d019b568e90972c849ad7a156d5e4f20f50bb5e5fb39afb3a447a98df4f7f7d1e72a7e17bdebb15c95afc0603ddb0b4c4987dd986282572c",
         Msg => "6531953e391507d0056929520ced0aa1849426605636414a1f8596c67a4231bc81b19aa8914ab3ed4eb1e36be7e874539cc43a3a7d9d766d744af985854c8d3b554a907de9bee2c1b1ed0299c51c73876e016513e878911c6677656c5744618fe8e5c1e4cad95cf43505cc032df1cfe50434ed13202d5bfefef420a377907660",
         Mac => "0b7ae7ecf74b17eaf751bcfa7cf35fa4e80f5387869d40773429c59e5d4f8e70");
      Test_HMAC_SHA384
        (Key => "5e675b4371a86ecfc11b2c89f59a9ea972c7698f2c964562bc0cb1f7b446e6f42fbc0935acc7a46e1c615712392ccb741ab7e82d04fc48bd842deb75bab02c94f868f3b08c362d57d9bf79f7ad7024fbcec05837d6b5908641aa4fb1c54f1293e2f1837bb9fcefd221befafef86d9285b76c217649ca07051e0c47757b2c803b14e12060dc21d4271ce443f0c22cfb5cfc",
         Msg => "a3cd8e7f41ac042091604398ca0f62f0e1ae18565a802cc35fd92cda0f2862121834041788a6ab6ee0c806586a8cd0facdd0ffbadfe03fecba3d9eae129d8910c632f779b42fe446d28901b37bfaaaff064c18cb9dd4d8c44c3d7b81598790aed44ecf6b6e5097ef8f2a9b71a262d848b4aaca513d63df913d612c1b8bee5e34",
         Mac => "e5d4c900d1ef54282ddb2e7028deed0fff987275be71d904bd42fab55c45bbf5");
      Test_HMAC_SHA384
        (Key => "64c673e5532ce4debe2682a3d104eaab398860797ff0c4c09430c1caad80481a50163d51af35704e3666ce996006d902ce0055859adc4471e9f915cabf1619eb1817366f3406df5232594354e073c59ed26dada8b1151d5ad6374672171cdb25e151c60988a91b32da854a9bfa5398c86c55d0aa6ca435c38474bc8b5d997811d64b56e553260a365774493856af39c8c4",
         Msg => "1230545c1ad282d6df24e5e35a0f544c3f4545ffd2c941b3fcb195cf9e2b4b8825be584a5fd2175a8d73f6b9b952704b490c3b38d5afc293367bd53adfe59ffd71e2d90289613e67dc193f2a8786f746a02e611f1129c920a6e080a36415d4111d243f4a4188df47f7a026fe6cb3d3856b33217b2f3e3ea4756afed3d5c2d10d",
         Mac => "bb51f90cd491daea50cd34d3c0e73b7386d93ff9871f7ccffc9d95adc62cd233");
      Test_HMAC_SHA384
        (Key => "78c0924cfc00a9bccc71f158e1b9c41d13e1587edb089fb35d596b55a63ad62832c6e138b17e5b270a3b05c5a168f3e1d66d355fce6eb78b753666adc36e94de3f139e19c227cc957ea678523ebb73f2ef34a4cb6034f23a4627653a83fb8735a88e111ab862c3af2f989429421c0bfa691dedea1bc01869d815af236d4a77d6741e81601a990a1d25fa9f6f35f2859e49",
         Msg => "5ad11407eb3acb52fb72295ab8ff76de2fccbb4c6dc012ece4951f5a11e8df395c8ca026402451ebabf1fcf5a8e891093b08e5328ceafafe489a81e945a59d1a6573ea4dbcd7be11f5e5af33f104557ab244519478f18d512968c60ff62948763c2ef965a87b992b9ff748fbdd7a499a5c27055b77fc534d4fa7f6b36e9b67b4",
         Mac => "477db58315957a9d4281f6b6c1810a401c73d7df6ac839a8784538a10b293dcb");
      Test_HMAC_SHA384
        (Key => "36dd84a5342524a4dd7887aa7eba8f612a8505bf0c268c2efbe8d3ea4f960faaf33ba982bc2c3308f948a1b64c7fb68fb891bc05fa18781b1dc95dc749f7009adc58cca2bb0cf790ebdbb4165bbfab9304a2a6f234688dcf273094dcd8d7b38416be57cedace5783d8b92993548256b5373f2b4e621eb19442a6e0f3a53f10b0ccf5b0ccc1793a2beb6866f5dfd09f3d79",
         Msg => "6dff76ba60cc61480efc62d01545aacfd41d25922b725b94819c94070c903fb14c5694f9d9bd79425f4da277e77dfde758264d543d381446c8acb7a517b9dd87b74b184767b1c7d71e953b574f3218e66bc1feb8a83469680127d6907d142898b5c649cb901014b052be7397d5ccc47215d682e6f3d021a232f739f0c607e789",
         Mac => "b0c443297770690d2103552d566b2e2bffc3e69871e1b90aa48609eb5bc94cf5");
      Test_HMAC_SHA384
        (Key => "b3ab0ff054819c5343a88e8ea9717e1c22ddfba4cb5f3ad89de2099df90e056c83c70df834f7f611ab8e80c8c4c789d46cac8134b4dc1e16248c51f851cc780db10bd5e2afde3f41fbfd1756248e7e1068a7c5cacb0e252b6643b14a02c08816e57f4ff6ecbddfacdafe3a7ff051c499bed5b0ae387cb8de0c0f11dd33729e51c62a647b141c3e1af197d18c5195c33715",
         Msg => "7eea726322a48f664ebea63bc1cd7ede984b402463522b9e7ea58ac09ff0e342ab5172c7ce16d5bdcac909848f6a95d20dfb055646429a9ba7ca4030982bc006528b3719f065c752c9898cacfe64d2974f82859a3351e83b27288a234687777e1aa1aba1b217cceff40718fd35459cf407e8a63752097e46a7c751e3d08e6e73",
         Mac => "4aaeb05e3eec82801b11606cc12978d5b509438412343bd292964c003424074c");
      Test_HMAC_SHA384
        (Key => "26da41f4d72a6d5f059496ef7a08fea8b8525356eb3f3bd11d013080a9d48e1cf2e2eab65464a6fc5b0bc2b8339ef59960e4fd36afc433506dab6257d62ed930d0f1bf36dac7a77f3f1a64608f8e1f334fe1a757f0160779fed25e129a06eb312ace687b4f999970188b24f0751fa3fdee11f8c2947be0d4383eccb9dca3eca767428c8d9d23a3584d24a96fcc9aaa7fa3",
         Msg => "ca6fb305a240774c51e5aa8d423692819cc7457daebc23ea90dea4f507ee5487aa391b78436cc20078aab36eabdc001c1e48a7a25b66154ad3eee8c4c536f91b61bb9ae82efd1cc6a99195052f71dfa31c96e47735c919b043b6497e0142940f381eb7bd299c8e862bc2d7bc959e38fdded88466038e3a04295b4e8b84b92c4b",
         Mac => "d62bf0f254e4eef3562a201d8837763af8d136e7f045bca38e34bb75667effb9");
      Test_HMAC_SHA384
        (Key => "816aa4c3ee066310ac1e6666cf830c375355c3c8ba18cfe1f50a48c988b46272eac0f2f02a0a2d2fd8fab2e62310cbc73fc0eff90a818cc7ee21049a095bf5248babbedf60613fb610f5e001e39ad4b748159fdf77d0d548562a257a991297ec2ed41278d832210b1ab7f6a15648b07136fcd9644b2e33ccf4d0b4538201cf3199e2f5a3d9a65c98bee9ffadc543e65bd1",
         Msg => "d0db3ff9cf2da10d1edfef389ba71780cb49e05dccb87c088b7e60f5375f539ef539c583d52f636f0406e8fc44cf36599ac7a54b467b9b72f8305dce41812482484a74d7bec5a98314f3d32ceb3ec328cc5c668719765253438a9f163e0ef89d32d6f1fc74379bd2b46d57ce783ae772c9d0cb172bf1ca32d355cfd5154cf679",
         Mac => "291957f798a32c65954d31289aac24d62ea47469e5b1105cca372eabed44746316cb24fb13c24853");
      Test_HMAC_SHA384
        (Key => "d9aa1a8f94471a4c69e71fd256df38c600924b42a595ad1e5211f06e5669fc4bf61d61d762efec7be844797368cc078d0865122d283d1d9599378e630991be5bc2c3516795aac3dc10e544fff880c6c8f3cf54e6849da5023c87f1482fa20324a664904913c1c7f84a94297fed419b002898b9739ffd6eeea5c6c124afe5f22d08c7c685c67c1f56fc17cffa3158aebb11",
         Msg => "dcda25e0850a555368ec4adfc4135e47e4f347374e42eccd3ea478575286ad5f874a7ce564a5d2eb7546b437fbb98e54e28ac8daf3ad9bef4b1d230e0cc4b507529b724769121c5a3db229ae1101169a74a6fe9e71cd6bed07cd6c28d908e86d25133190fa18dca8a678d1ce6eb49e21838d110e316a05ce58fb7c2f201cee98",
         Mac => "9711173e1c86fcdb11b7c224ecb76ba390c2e1218d26f353980e656a08bbaad9ca8e8f27c0aef6ad");
      Test_HMAC_SHA384
        (Key => "7b2d69ed2cbd0f37dc44f26506e4fbce7ab92593a50fe07413d2b3e83245246c59f7dc1b08f4077f7238faa73869187978c5f64a0659bdacf973d0876a5baf6c783e1c258f6b7c91ebc27faf576803f83bc036f2d597fb02c79f9081d21f6d13e1e86f34498b35144fc9cba5eb4b85f2cb942eb29b33621d843d39fef2fa260a9bdf1e70bdbcfcb1a63724b27a79661031",
         Msg => "7f737d59c6afd85eb91237ec52c3f4845d6ae92921423315427035abe693e0ad179c32af69e0fdcbdc6bea970397bd5466dedb6826ed090fdff9764dd256fc274446a312210f67ace5503baabc944d11e8288caa642a68afc7e3d8cb6a57a242cd19d76b37649c679d68300dc5e22b24acef04d52422d65fc1d4640df6bb5a66",
         Mac => "2aafbabcb09f72cc887ff2ea74e59a271afa5f160e8cd9d8b5fc9913deee6c9127f59ed78521a516");
      Test_HMAC_SHA384
        (Key => "a9c911ac37745172987713087c13a84edab4dbb7e1197e9430b549954955e58c43044375c02b32b41ffd319df3128139b3527f47b315318252891f22755364a5357904cfd57f80f0f7d0a8650f60b161179087ee8552642e7a8da2e73cc3ce3ee6f1fdc35eb663ae88b82168b9445f4e6f349bb13f1640210e8a7beb84ec4ae0be33d658431902773a7d44afda05b48621",
         Msg => "9bc97c5dc1b1fb7ccb9973c71382af696a0e9c2eb7930939e16eabf9ef9a64596e81c4371311d118a213031a0eb8932ae275f676df11a425e7fd1d461ae32e073e81702864b813afc8e0d9dcfa5f655f3b7ab6c92a6bef41a0b35978d8b1aadfd3748817face49a806a9fdf71d9eae723dc4e60edec672f3d3396675722c6147",
         Mac => "691863b1bb5451493fcfac2843cb345bae42785f1506f8bd8f994b9d044c07600a8c944140419eb0");
      Test_HMAC_SHA384
        (Key => "c1b9199017aca6fbe0741e5f9108b0fdfa43dd23c1868af30fa553658901239082f101256e672d3c9ad06c531b3ba09305be9b56dd1535e7508d9c882421ecba70e200b8089c87453cb65aa7c25a0df4f0d6c38c2e4247e7ac63599150d04672f353bc53cc92db9e2cef8f656cac1ea62453fdce9e55e87b8bf13186f4575941730eddfda29352d0d443b495037afc330a",
         Msg => "92621ba35ee326197b59a3464832972b9983169dbafa63e0b1145877c48f083b3b23a4ab676d9b83e32c05901aaf42c2098ede834799b847420e6464cb0fcd25d5521f19791be4b13e676d0a986a7308ae3cfea460d08687892558d781c03c51e75955989dd548cc1374a15fc94c72240ff63ca9108713c70ec1fe77ef8b9de7",
         Mac => "f1dfdb6f3b095c096d342819a21730c76fe46626adf3c27703a207ac21b509a61779e6dcffdf9847");
      Test_HMAC_SHA384
        (Key => "1783e40062c8e1e84b6b23df731405e4a4f540d815fd5748ea4f3288fbf20801d6ca83cb07c71f7f975cd446d233f4364d1f56df2852b42091d052408923e039eb50a257aa0bce025a2736d8f2502600d0fc90bafd9f663ab31e48b61c875fbe5dff89ccd3fcb61c9cb492bd5ad564e9337635921d4d363d58235c133b864d3534be7f510b029e7366eb2f1d9228749980",
         Msg => "7f44275cd31c629d7833517c19d41c5041b3bbffcc8a0cc39c05222e8ddce06caa3ec7c9a1760d7274c9ef80729d483266e1617a0ea80bbcce17ebd2a682165362d2de15102aebf0b7ca8dc5463350bfcb8bd1d9e544d1a17cf9883baf983ba80ec611490a7f239ea9fdd2547fdc5d7fd97bb3243ba585fa0d71a07191667af4",
         Mac => "a63d553fe411517492f32b274278bf921370b8a70a27b835176a78b1d812a95f11286e65dffd70d1");
      Test_HMAC_SHA384
        (Key => "decd5ff6fa8843501dcea0e98730d868d32d7af02a9c17a2b74a52645ae337e1a116ced1f4f4ef7b0f995778b60ffcb9a36f9eccc4499f5aa34614f5260c1c107862714f47953c02301a2eec7774cc48fc590a0e6a101c72b21d89adb82081014bfb70f75b33d3ec66994bcb3429ef1cc432e73e86b737f0cb15d81779e70dbb0327f45298965b419b5dd6a054f40e3de5",
         Msg => "3e3c5774c11abe73629e400891857106285299254da0b6f799b6c41d7a5c3bbad5edda28f0aea3ea905e27e25e0e03c48f33abcbc4fa66ab2fdb9ac6f8714aa2df89dd9b227921d5a1b38f754099d1118d938164a35f34474ea9b7dd6fdc980da237e8351f23401cdec40229ffcee1d3689aa459b07926b33c48a2c8a7442de1",
         Mac => "dad2422f9474b3c8cecc73505aefef0b5bd8e23d70e66da3a71578b7b0499546e5c9ea59ead1ea9b");
      Test_HMAC_SHA384
        (Key => "74b555fb6542cd797d87959be910db67e9278ea378ed1e8d2faa83cc676280a79ea929751cb7a354d5bf2b1e927d59994c0fa6eed8052d5dcabbae2e93e7d8ebec6ec8cc787ccd73a4d36ed9d363ae89b81b8e0c0200d4a43f7c0b3dfaf8cba027ad3aeac2b6d33cb26a66b5f3ea609df4f64de33e059bca5794a1dfe6bee02e170d88b541903e19c72d1c983c39f93fca",
         Msg => "769b0eff7e7bc710d9fbd289ddea554ee7ffbc67f21bf36168cfd8f1371ef0db288458126d37ff2178ac13c9145db9ecaeca01aaf3bd19c9a1d3c15a9638fe992eb21316cbe1ad12b5c55e2c25804c3d9c5d2b80791268f6cb42a7086446706f2f2d2551c30138ac374c9af838db77085ac22032aca149af8f257444c8d1ad22",
         Mac => "23f73da7fef0c97e39b5a9cf19fb52507443fd2669953ea3bf4939fdbd678ab58b2bca3a4430b203");
      Test_HMAC_SHA384
        (Key => "087ead1bca05ee15f09e46ec0ca272f96841b609edd5d754437069af3ab7510269f482fb15660a0454dc52737182a10193fae37e9aaea9c34a6570e7ab1526b6aff8ea5e16e2146c8fd275f720c7e01bc7d5e8aa6277ec1dcc2751d1492c0f7024b46fac96221334eaa936e0df1a352f4efa4ef40cd8a84c12dd94d3dba513180e4d984e5dce0f44ad891d977723aa266e",
         Msg => "e4476c025e67a3d5bc01f3ce55e578e84a807e935b5ef156ffed14b7b384765f92a3237a267d175d7eb3f86b80630439816148f013c412f31ea5aac233233d1f1caa1a6fb8762162065277d67fa67ff9a9b006aee912be33988dee005a0c67f2abe4baa8bb5aa82e7c66dad8f9b6d371e9f62295844fdc5c952d4939d146de21",
         Mac => "42af9bb87aa1037114f53189c0d05b5197f42083fa6630445e5021d81f525550e8316d25ac5e79e5");
      Test_HMAC_SHA384
        (Key => "dc454e19f3e1181ff3ef0553a81be2dbf3cf3d9d704d28f757fb39b1a0fdd5306b09aeec9e778b24d09848d066491dd7fbc8238206c61330b6bd514c21832a7d9e205a1c6fddd2eba49db8043b70ae0f8c6657b8e5a1176171ae1b135e169abb3e2f5a93ae3875de36a55dd871b81eed6e51e3295507bcf04e779eef9edcac5213e1b437a3b3fd63505940344f48f4d768",
         Msg => "8e4c5174a7a7920055ea1ba5e307af6c49e71e33fdf4bb4f0bdb0f766890cfdd83920c9d1e70aa5b5c8c13281b1f2ca6837d896cdf9bddacacceb413f0d564f1ce1a409a5635100ca2b2bed21e1452282719205fd840408320893f3c187c14f2946c5634f9fdac5b4ee4846a95ee08395b444dd38eedce1c8f941ab7888cc926",
         Mac => "cf6666f246b6bc5cfd0a9bb8184f8c0057d62ff8dec5285c2d9fa18bffcfec9663374422caff1add");
      Test_HMAC_SHA384
        (Key => "c7d57e7568f937194e12ceed4af8cd23521bf054326a7e7d7e73d947cbcb548b1eb04615a5ed5da8a5fe3443b47527a3289c6609cf5c483de15de2d3326fd9adac2974c1fdcff51c8d792a27b3723f2a28dfd60ebca15967477c8fb2e3786eda58873102d869aa7eedcdd822afb9bcc03a2b69ec5f015b029a16096b44aebd1b0a14a45e9e8121d5ac4067bb1010476d46",
         Msg => "4e462ff4568a9185c42651cb9cdcb7408682d20825056b18a5ae379e93a4509df2b3e6d88b4b32f284ccacd334007e4e36e93800bcbec57b26309ea4d4f13d593877d5572ffe405b91cc398806b8cb091ced09f797ec007d09d0ea3aa2d6a5e6481c6339eaa9a20812ae5fb2ba0b86ba6115aeb55e97036773178329a55a6e8d",
         Mac => "968d6d68367e361e137ebe60422ed2c309167402038c67edc11ed9961df1bb08c359996740e0da83");
      Test_HMAC_SHA384
        (Key => "cc65da6fca9702fe44f2d808bff6aa3591b21f1c4792c0b74379b613aa0fd54c7d5ddab90597f16475387bbdcb540d8ff72abc323ffa9803e2167611fb3af319a920b5b56d50f4d0d336395d557666487c84f7ad486f8749d2fd962e30fd89ba99d9f2c9c96b122aa7119d502604bc4a69e558f62a9996715c579ed10fffa11795ae1a5fe38f545a39f42cfe06a5187c06",
         Msg => "b04dac9b967eaa2c89f887f25d4b641fcd566eb71c60a944fd64edccb1ab2e006fa000b608e15999cb92991fa6f6c9bc8f40205622a6ccf88cb8efcaa7f0e741668ad2937495516e184b8de95c9e78bb6e1356aa46d37b47890056d9ae45ae975fb12c1a22c51a1138cb6a37c56afa823278169dd00f3f99bee32ae00cd20c6a",
         Mac => "bb402a160edbf81ad5f32e89f3ff51483a699755b31ab50c03eb50f4d02a285cb4ca49536e16f1d3");
      Test_HMAC_SHA384
        (Key => "96f763e5bffe0bf5bbcd9b942bcfdb3e32ed26ae2a6ac1ea960b6b7f587c350e25ef94073506b5b53ff3107ba4de405deb8612c16d2cdc7751ad10f8bbee10eb417c44ee9f746b92aba12ea78be5fbbb25da10ddd7b8d6a7687a717b3f3c950cd3e89b206311d495e71f1da246adb360c92f4989d0d8587fc4bbb7904c306b78c479c027eba599c5dbb504f43ffe1155c0",
         Msg => "b59d490ba4adccaf7255d9b6129013866786912b58539041230a6415f3f9b507b42fe733263cda503038d4d77807bb6830da886b33f9f8f350c184e7e5e89463b009f05ce35c778376c4136cc110ecf04a7adcd0dc74249ad9a55dd1d02eb14852314acf02940b11ec027ebd18330ee45e6e77a37b4c7a0165bed51adc51727e",
         Mac => "7a95bdea413b7997f94a6d16152fc254bb5f34f2e6d62bdaca1efb7fde569e5d8068bdbb7ace2609");
      Test_HMAC_SHA384
        (Key => "f7d56910205345c18409bbd42bb13265d8cdb1b0e1304ebf3dc1ea46df7c1bcb42b96a0946b1bf973a3e19c53ae282c7bb0b431564955411209116ea714544c10773270b91df0a37d30bee90f8457f642ae3466661ce1f51783deece86c38e986b8c0adea9e410e976f8a2fe0fe10f864ede226c7fe199c7704ed8b9c7ffdf96988b7a4937c8b7f44b8e9dd724be1b734f",
         Msg => "23db86c1510c083f02ae3d8c9ca54dbc2bd8540c4c8465d349d7cfb585ba9e1a1bee65dec25a3b4bf4a304444ffef2c23b424b85cd426c03eb590ea5b146c832143ad58bc530189a587d5d85a6a8e227707b16c0455aa0eba5d4a3d16678409d57ea5d302436a5157963d0b76a4c25d113ab3d277b770974bf7017a36cf81041",
         Mac => "cd2f37c7d7cb19ba0e8021dee4a3af5d53e76729370fe2f05df74eae6e9566814af0ddbf3d23419d");
      Test_HMAC_SHA384
        (Key => "4810d4a682e216f0b461a373efa1469b7f18b31ed5ba1c3ac562ff3ef274424b86c0815c26aaa7842588bb77f74cfd4ce963328110dd3c407fcdede0bdf31daf7798faef71baa01ec269ea7b417187c53b39504667ebd8101bd54587bf105f1f835fe7674d592a47f5cbd685b5580b8edb62b574c12e1a33ff42af38df12302412dcefcda1d16d85267527a03b48b23033",
         Msg => "1ac164a39ff2d0a2195f3e7c5e506362f016dfc38a4c70b7f95d669e2d475704909e13c997d3da7e96b6cd11d83aa3adef789ddc49f7bcef042b319f033b15f442085a66666a024399bc8e50949cbab3fdec6710f41cd9f3e9ac226eb0ecde03d70721c3373faeb8c97a6a81bbfe103cc37925a9b4442f8b4fe822525be21bf8",
         Mac => "f611b272c28453f7afa7532e2c06507c5fffea12c1e7282bff8b1c337e85132911f67ffe76c00a89");
      Test_HMAC_SHA384
        (Key => "f05d561f5ad70403264c5e0a0edc12fd473b19c0b40f8cd85a99ba2a14987705876ab76359755b6c9ec54a3c93f6c4e68f55f3b93642c3c2f0d9f4919ad16e407ba3d4b279ef5b198c1cddbb744029f5a73f9e808e36f8f3f01a6989af9cec25b250d693220fad11d99a3e0e177fea317741419d22b3d27443a54099bbc299bb15b9e48fbc9bf95c6b8496bde67eaea3e8",
         Msg => "77d3f3e647e67766e5f4cf1bce5f631bd575ddbd02f29643a0c64dbd92191f2ae68db3dfadc3b62d0920873e87d13340af0ca3c5da99146a4492c8b76267fb477624192960f72e85b7ed9e8318fc1668be46c203539cc1470641d639def1600d4e228c8b098ac9b817e17cb329e8f5dd2aaaa23c160283220f5dde09aec134c2",
         Mac => "724e5d2d51d98c15ce2e78f861d7b6f8952882e9d93d40850b78a23e632c4e14a222ab3726b1a0aa7c6b2cd66082ed95");
      Test_HMAC_SHA384
        (Key => "95ece1c8ae5e94d16ec9983b1089a37395ad5b1d660916c13c87e4c13dbecf8f68c6611c324a679471def5487a93aaec86c935025b4518962884ac2cb04e66f7aa8e584b6860fb55b86c2b0a0873735dcd278bb525401f9ebaccd2beeac6830c26ebcf3c98c9d77d09194367014e872f306e641e0c21b241bc085e61354faf35a386cdd70aac83752d8d4449af4f6ccb78",
         Msg => "18dbab9f86b9d70bbdeb018f6a76ea7af23eb2ff111e9be3c13811795d8ae7d006c3e42b46547eb1f3c9e566565a435a8dbd42212e3fd0822d131f7300eaef4600c40f1d130521a388cb9ffe427f1bff19aacb9c7d0a44a15ce686a2469e3934d086365d36f449484498353d760cf9d15eac525a46a881a617584eed79cf4d03",
         Mac => "2be1bd6a766e30792154cda00af97cc512e81413e0fb761698f39a26cecc3face6f9a98b7c49605126dfa5aa8de1ad72");
      Test_HMAC_SHA384
        (Key => "70200eb90526e89d3d139d4d057398534fbd7d91087dc0834ab270c4d27553d4b4dc38184d1e89227af82033074f5bfe6b1673afb272092cba1c029ba20895248044a2f8522246923899ac3de0e926d6417e7cd38c1784845f27f2993c7b72e53b1ef461fb7a4774debfea7176891f623abd40047eb35612a29be8c68919119e4c33d55c306db550d63281d9b2766e2abe",
         Msg => "1e6a0d7f4bf483287255148e2e9346734c14751421a6c55121c35b0eae12cdd92e30d6cd60b14fb6f0625a7649d1e1a7aa103f817cb53cfee3253f3d9313bf24e543fb4a2994eb143e3d761e6157e5dc439c98815e6ef71f881bac10c95f10966a2ae2be4ea43f8a866ece4e1f2b3c5b3e40e8db70d7dffc3b2a0a51f9fea675",
         Mac => "40497133e82d9b6a335002f71585340da2fdc6bceb03fd911c82abe8715191624671bf476b89de4d9a7bdade775ac744");
      Test_HMAC_SHA384
        (Key => "332b091239699daabb4df4d8d45527a288437b8c586791011420ddf5f1a159c9dcf17b6f0d3564cede325a68de0e783a2156a4e3db46c2092d4427f93fad518d8fd4d553894898eb575642b1facff09d9a0c2a671a2e14eef0aae8da3406a380f6ddff07d529a2c9cdc295fc5121f7929a6af35d3eaaef77045c06e1f733b96ab913e1d31a60e830e97c39910b8bf5e2c9",
         Msg => "64c479cbb5c9c6167db18c881f23699354c8f4c67b4facf430b52f931fc3ad621ad89b4f6ae8ac9763c5fd2f3c9d8f631dc4fbbd78b461289d53a2558974cf5eff9fe1a9db15aa10a20f0b3e5d47685ca8b959ee06aba2f777eb66644d5897a73ba3b1a3af57a8c861171e7f2c27dac81e2f7621cb3b57abe605e3881277ed87",
         Mac => "ad69ddfcbf2e6383eabb9f561d947eb5a6cdfcfc220f506e591881291ae85524394e4b4568eeabf1b0103d07fdfbb8da");
      Test_HMAC_SHA384
        (Key => "f87e5d9fa8d2745f9aa442686bb0e372c190db05d42fb58f2e80ebb4af7006e5d3190634383804665ae1164aa171734a9fc5d84092a92a8b31935c61a5929366d581887ee6802ee002a5966d59ee0f3f667a918474f95c8d6062dc22a0e4d019841eab27bc923af51b5788769b0fff79a019cf7a810894be4453339fa94d04246b5837d4c25670cc2c61b5106dbc8a1fd4",
         Msg => "38bd6300e7ace5d0be9713b5fd4ece221bfde5b80c5b7e14c023b8ececc88e5a0c65ff77a9f26b2cd7be41450319d7c7eb519984eee166ec86e4372613d00260da60de634dd2676a8d5364342db8a758396e35d976b4a7faec07d053a2dea025a99848eb5bb39f31e53ec5a90391067c0b3b01de2d3c09e5f975cb9b215c3152",
         Mac => "f8c0539edea90bd9cec6a408a9d47dc2e341a68c5d91fb8cdd48c13f7667836dc4b68c8ec2519121a3fe02e571dc5c74");
      Test_HMAC_SHA384
        (Key => "7da3134a85e28a852e16a552aa34d3767d444a583c15f05b942f7c6a8d09d8d5107cca5ba878d48885f65941c62d009df8095ef6d9d9cf406248a49a058e842334e70c0f2244b9facd41087b3c58dbfd05541fca1308ac69a6406c2a9bf8c0ffeecc1f8d7db001830fe1fb2b941c2b3faf0dd6fd710a507d68011c43d8af551148134cfe402373cc52bd7a7757e0b70afb",
         Msg => "c523fd03e54f1046e7282756f87501c6ed0835a233e6c6af09a8f7f5ec21607b534142529d3918d448e06e2e6356f61c46e7d9f480324be6118a6282da9c287a5152efaa79f8e455129ee7b20cbd9aa7421db8d465f5a9d3365553bef9c132f2261eab1361d39d51ac283ae9dcf115ee49717b49ca7907ffe1d071b232d7a76b",
         Mac => "b1fc08f7a1d0bcaf9cd23024cb0f9ebcb826d9facf84c50d644031ce69d99f5d07eb72e02e25b0a3fd395759552d0dec");
      Test_HMAC_SHA384
        (Key => "f85000b579f5db06206f5cf43e9f700e352bb6bfd37e7c76de10e903f0e77b45855eb50253251116da893cd03bf582994db987d6ee0b3910974b0252348c42d3324ffcd5d991d0cddc0929c42eabb7fd187020d88959f2f6adb2dd9ec0941f6025ad3ff8b243fe754f778b9abfc7f684bdd7e78d4b71907147cae0af3f07f93286ffe531874384545a5cc9189553267465",
         Msg => "40ecdfd2810f09de02dee7a3d82ad794fe124af3f81d818cb78695a2bdd7ba2a81b9c437150bebb60631cb5b84afafdbc2f60e5ca07d56298814e9ab95766595fb1d295ea35a15f415a490af9b31d083a3c3567b66c5b762c796a2c37e251f1575be152f72230f02f7df3f8667d7c4f569222838911a2d9e3eb3c9d4be0c6f12",
         Mac => "c2fdc5b35ee992e0cb4c761a705d8cdeeca26edc2e392419f81173b478cebfb3bdc8787273639da8882020150ef120a8");
      Test_HMAC_SHA384
        (Key => "59f3efcd2fc8ab28aed9165424c8962fc883b232fa767649cc0019e1c224dd42d682371fbf85306b73dd0b6feb30281a260c289870215226e4ad352430378f6b98806ee23eb7954ca0ec216462c76d2c4e7a328299f4f3f4675798d592ad5990a7d7dd3d32c5a3723ceda25c11f52c0e47b31818fb58205c5ee8881d71ee01590c6dcc59251922864fc7d47e81232f6719",
         Msg => "cfb0db236306e51c6b540bc1797409ecce36c4fc1e0d2f2793086f1214043e9ec6218d05d3726d276bf92f1e09d2ca18f8ae7e661583b7d0d682342c8b4a682fe45b2182b4cd6718f442a7c00b1911f64de43effc11c16352714f19f392cfcc43247dfc18d7f9c9a0f17bace07b0a42ed5c04ceea94113fd8da6ed92a613c008",
         Mac => "761c1b719e554e261f783334770d59879926a641bb5f8db8583b43c52554639d4f00e19e9e08bfef181a406e68a23a2f");
      Test_HMAC_SHA384
        (Key => "e6fae88e7e75e970646091815949c55f9554a5f85d82c1efd83389411fea06289351c83f737d20e7ae728feaf5ea7d5f15522ece8416f394391e9d88c19937de90f9f54c953e676c1178f262a88781beb92678a4eb28ea2a08000b010f87e85884fa55fd0b4227c53579a42f9aa9384428d76ac1ba400d78ece2bbf42e3e7f5c185dd299fe11c9bbc37d8c99f2d70ab80a",
         Msg => "d3d906f23fd6893e241066457047acf137d3a374b396f8db89301be64d71e61749147f097aaa7f03dcd454cde8b5e4c25aa77227372dc6bb0f2a888f7f50ee18fbda9783ca7eb648529d720296be8d7efd3a44125538773017dc0a3aedbc8b9871941509383a74360fd4898d8448f04ca9f4e1dc14a054612ab0698f9e9e06bf",
         Mac => "002b1474834e0bd0ef8baaf4b38ee412ab1da2cad89a54ecba9cc8e5a74b44a9f663e23f6dbf419e1009766c3d7275cc");
      Test_HMAC_SHA384
        (Key => "321206ddf2d6f0c29b10e34444cad455a4324738824066446c9950e5acb4b3e3783b9de769b48f3b2f60d4d1826310875b261ca965fa11b7aefea369a342b1f13b2c1980721bd10bf94b344f2cf9991344c72aadce61f4c75c613a637a700f1de3ae24b0f555debc6399abc72ad29781c6dc1a4ca5be34fbdc8bbcda1986f6efd8896380daa8ddd6d311e3406436315a48",
         Msg => "19583b5e7cc08b189ac798ca2f45a83c345d23c0070de066c603a26efbb2e3037fa6d026981494e865b6d9dc7cd58cccd1a8e1abdadc98cbf0747e50f9d336e5441739adb4a91c7c21121248fb11b1da30eaf9c9500092a9f0a655804c330e79305480dd18a7aa3e968549f6f41f9ed01acc7104b3a156698c432fe63cf9f229",
         Mac => "88aa8e3dd920ad7684acc468021c4a9fd782766c6d80c339e81efba5121b22c80f872895a544c42a849b9c9c2838344c");
      Test_HMAC_SHA384
        (Key => "ec96c4a5f1b32b78a8439ef6e98dd93b712aa051360bad51f8beeecb19eced68ae2790ced6e202c44bc1f1973614fabc489e61b6069a063b640094929604fc3f23df22e23bd3d55d4a690535cdfe303b657d1e6b296ece144130b039b18215377249e3a9c78d8d89cec44298555365fff0523e36488fef25b6d6a98911701f9ac4ea3beb23181091ff581187771b805112",
         Msg => "6b1bb1f05d08e59fae3d06392a2d4d61f63432016a20dfeb1ef0e4bc48dc2c06459530ae75cd6a924cfa0d6fa657f3035b2cd76e1450c4de5deccd6bfb81ff407f2d94fc1b2a6958b597b3093a7bede835071550a01b17c7f90c8ae199a59a62426b45a3f725cb37109c5fcd8da02358ab4b536eb58ac0ee1dd881e6cb4de5b4",
         Mac => "bd4cb2284374d21c465ff20ebb88616abcae7c8a1cbd0ad966352c7a47e1f153c7e0eb62be767aa56fc5bc78ee5867e0");
      Test_HMAC_SHA384
        (Key => "0b0d5aa89010d5ebe8e2144e9a7a82a5fa6eab54a967e8655fd33fd7e8d985386d92c576f576e6f22b1487d662072ea9d625a22035f995375e74868168dfe6bce6147aa969ee001b47fe154d9b7f56788d8cc6a5d49170c079004defdd456722fdfb3feaf5606c8ec306865c4ecc423da70dde8c8e17c02838df5ac84ff3508f3bafdde1a0b473742796a1aa82d53a1eaa",
         Msg => "e68bd3073773cb4d15fef2bb61a0be80d5356a7a2f953f6092691141293d0c2d0dd6b13269c51b8adc3c87121e2113fee761c6cb0c87d176eb8d14ec0af1e4c1fb0c0c2483a01113fbb0bbcbf594d083234c23597515cd8d823abbed292d699078d6ecc7cc2b36513a0196ce2e217e76529f890bb267bc0c1d190d2cce172103",
         Mac => "8cf8f7217e2e9c3dcd14322e19eabcac17de11128f944441385ed984f07df8f446577c789f8d301f37c62af374a05602");
      Test_HMAC_SHA384
        (Key => "a0f93cfbd5f5ba6b0dfaed5310fa07eebfaa031f049b36b205a627e59d8ea0270ce1051fed1fe5f0691ecfbcabad67679378b89daf2ccc1667db7a1877a1803ea388d279a5a931546b94fe7c7ff2517fc76946d46ec0971c224470a7806a7e3accb54a0fe6dac51e7923239b7611edc0c14552cc2aa0bf4c9eaaaf999e30c3a2f13215eb96fccad6fd92e622775164b1ea",
         Msg => "66dd7620746dd224582e8857079059417407f79b06b11a114939d046e4fb1419cb69a327b5ad0b90d19005ffb49a04e4967a0e04bfa9cb343c4bdc61d6566dd445f50eb4a02fbecd18c4498fe657d55a82d2b7f916078b6c329383eac108ff263c4b5ed21d3a14619792fd128410f22a9fd79980f312813f93da6ee88c5af196",
         Mac => "6a186858094b8e9ac0f5b519a309fe89ee659b2a919f7f942a83da674e5163c65333e56458aa3bb29a11c62f65ff1c41");
      Test_HMAC_SHA384
        (Key => "a1360850ee9e253d9792b8736df334679990370ed58f6257dc0f67fa1e0b6370b9816f42a5d471872e7039a8a8acc9675ef4f320cb272a4e0d3e9250962f596e25104a17f4809f6c33431703b62c49e4eb4038d80e1827e4a087af10157d0e6ccd2bc255456857f58f547d09ff3b5de728bc2dbf062a02217d32e6bf02be2b75991aff86ff55402928eb9144eca0ad77fd",
         Msg => "dbcab7759b3e83d957896333952ca4329671378e7efffa41b6ac3af38f9275b6286564f3910438a4304d25c464361d046919dec07c502e313f0265e45e3c2d6b73448652272a0d559a9f7dcf060a76769fd97d46bd1545bb3c3a2c43234509f3850e2579a5d887525d27753dc1d237efff581e088a77c54677fb97f827d591b6",
         Mac => "2789ac4f72d6fd014b1bd5895e4812da977b8c6b3473a18270db1d99ebb9c47392400cf6a3300d88f8774f52b405486b");
      Test_HMAC_SHA384
        (Key => "044514e7de18bad8a149fadb8ce93228089129b739a346a8d3d200e12fe596f99eb70055fd832590895e4e20f505db37bad935e8af28038bd9aea162845ccd7d9258a4da1444ced117c3f5afc0397ba29cd36cd531c8b1dbd9de8751d02f30bf8b2de8c04be41b63f37fd5d0160e7a2f5586b7c5e809b8607a689cf63ae726892f40b54dcbea760dc49ad8cb1f0b40a78e",
         Msg => "3ebada6dcd96f06f3c2eba9a5f174c428b60451afc6a55a474f9fcec258c9476d1ea917530fe083d92e46efbc544a3a439df2e2b6267cbf75e942394d874daa92c03ce2acbfb9ecee2ed6ac43691daa2525b629ee54ec4006615d6d7f95085eb962c1af46836bc097371365b7aa5fb2320fb67d94dc748a7d3a59d1d52c79e26",
         Mac => "1da79416a0f61ffdd39cee60fa603e70c08061dbd9c1693683c3f54d6fee4a20006275edf3bae040df289495a89a6b01");
   end Test_HMAC_SHA384_NIST;

   ---------------------------------------------------------------------------

   procedure Register_Tests (T: in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Test_HMAC_SHA256_Auth'Access, "HMAC SHA-256 (RFC 4868 - AUTH)");
      Register_Routine (T, Test_HMAC_SHA256_Prf'Access, "HMAC SHA-256 (RFC 4868 - PRF)");
      Register_Routine (T, Test_HMAC_SHA256_NIST'Access, "HMAC SHA-256 (NIST L=32)");
      Register_Routine (T, Test_HMAC_SHA384_Auth'Access, "HMAC SHA-384 (RFC 4868 - AUTH)");
      Register_Routine (T, Test_HMAC_SHA384_Prf'Access, "HMAC SHA-384 (RFC 4868 - PRF)");
      Register_Routine (T, Test_HMAC_SHA384_NIST'Access, "HMAC SHA-384 (NIST L=48)");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("HMAC SHA2");
   end Name;

end LSC_Test_HMAC_SHA2;
