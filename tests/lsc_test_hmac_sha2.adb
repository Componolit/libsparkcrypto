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

   end Test_HMAC_SHA256;

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

   procedure Register_Tests (T: in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Test_HMAC_SHA256_Auth'Access, "HMAC SHA-256 (RFC 4868 - AUTH)");
      Register_Routine (T, Test_HMAC_SHA256_Prf'Access, "HMAC SHA-256 (RFC 4868 - PRF)");
      Register_Routine (T, Test_HMAC_SHA256_NIST'Access, "HMAC SHA-256 (NIST L=32)");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("HMAC SHA2");
   end Name;

end LSC_Test_HMAC_SHA2;
