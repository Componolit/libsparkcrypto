--  This file is part of the sparkcrypto library.

--  Copyright (C) 2010  secunet Security Networks AG
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>

--  This library  is free software:  you can  redistribute it and/or  modify it
--  under the  terms of the GNU  Lesser General Public License  as published by
--  the Free Software Foundation, either version  3 of the License, or (at your
--  option) any later version.

--  This library is distributed in the hope that it will be useful, but WITHOUT
--  ANY  WARRANTY; without  even  the implied  warranty  of MERCHANTABILITY  or
--  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
--  for more details.

--  You should  have received a copy  of the GNU Lesser  General Public License
--  along with this library. If not, see <http://www.gnu.org/licenses/>.

separate (Main)
procedure SHA512_Tests is
   SHA2_Ctx1, SHA2_Ctx2, SHA2_Ctx3  : LSC.SHA2.Context_Type;
   Hash1, Hash2, Hash3              : LSC.SHA2.SHA512_Hash_Type;
   Message1, Message2, Message3     : LSC.SHA2.Block_Type;
begin

   LSC.Test.Suite ("SHA512 tests");

   --  FIPS 180-2, Appendix C: SHA-512 Examples

   --  C.1 SHA-512 Example (One-Block Message)
   SHA2_Ctx1 := LSC.SHA2.SHA512_Context_Init;
   Message1 := LSC.SHA2.Block_Type'(0 => 16#0000000000636261#, others => 0);
   LSC.SHA2.Context_Finalize (SHA2_Ctx1, Message1, 24);
   Hash1 := LSC.SHA2.SHA512_Get_Hash (SHA2_Ctx1);

   LSC.Test.Run
     ("SHA-512 Example (One-Block Message)",
      Hash1 =
      LSC.SHA2.SHA512_Hash_Type'(16#BA7A6193A135AFDD#,
                                 16#314120AE497341CC#,
                                 16#A27EA9894EFAE612#,
                                 16#9AD3554BE6EE9E0A#,
                                 16#A8C14F272A999221#,
                                 16#BDEBFEA3233CBA36#,
                                 16#0EE83C6423444D45#,
                                 16#9FA44CA54FC99A2A#));

   --  C.2 SHA-512 Example (Multi-Block Message)
   SHA2_Ctx2     := LSC.SHA2.SHA512_Context_Init;
   Message2 :=
     LSC.SHA2.Block_Type'
     (16#6867666564636261#,
      16#6968676665646362#,
      16#6a69686766656463#,
      16#6b6a696867666564#,
      16#6c6b6a6968676665#,
      16#6d6c6b6a69686766#,
      16#6e6d6c6b6a696867#,
      16#6f6e6d6c6b6a6968#,
      16#706f6e6d6c6b6a69#,
      16#71706f6e6d6c6b6a#,
      16#7271706f6e6d6c6b#,
      16#737271706f6e6d6c#,
      16#74737271706f6e6d#,
      16#7574737271706f6e#,
      16#0000000000000000#,
      16#0000000000000000#);
   LSC.SHA2.Context_Finalize (SHA2_Ctx2, Message2, 896);
   Hash2 := LSC.SHA2.SHA512_Get_Hash (SHA2_Ctx2);

   LSC.Test.Run
     ("SHA-512 Example (Multi-Block Message)",
      Hash2 =
      LSC.SHA2.SHA512_Hash_Type'(16#da13e3da759b958e#,
                                 16#3f14fc1428f7f48c#,
                                 16#a17f9febc679778f#,
                                 16#189088b6adae9972#,
                                 16#e4f700499e281d50#,
                                 16#3a43b5c4de991b33#,
                                 16#5426ddb6ee29d3c7#,
                                 16#09e94b875be5965e#));

   --  C.3 SHA-512 Example (Long Message)
   Message3 := LSC.SHA2.Block_Type'(others => 16#61_61_61_61_61_61_61_61#);

   SHA2_Ctx3 := LSC.SHA2.SHA512_Context_Init;
   for I in Natural range 1 .. 7812
      --#  assert I in Natural;
   loop
      LSC.SHA2.Context_Update (SHA2_Ctx3, Message3);
   end loop;
   LSC.SHA2.Context_Finalize (SHA2_Ctx3, Message3, 512);
   Hash3 := LSC.SHA2.SHA512_Get_Hash (SHA2_Ctx3);

   LSC.Test.Run
     ("SHA-512 Example (Long Message)",
      Hash3 =
      LSC.SHA2.SHA512_Hash_Type'(16#6469e70c3d4818e7#,
                                 16#63b415bcc7422e4e#,
                                 16#2844203bb1981f8e#,
                                 16#eb73a9af03a83256#,
                                 16#0aa67e8744f20fde#,
                                 16#1bc377e52c43b04c#,
                                 16#2eaa492c5c9c00eb#,
                                 16#9bc08cad17b2ad4e#));

end SHA512_Tests;
