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
procedure SHA2_Tests is
   SHA2_Ctx1, SHA2_Ctx2, SHA2_Ctx3  : LSC.SHA2.Context_Type;
   Hash1, Hash2, Hash3              : LSC.SHA2.SHA512_Hash_Type;
   Message1, Message2, Message3     : LSC.SHA2.Block_Type;
begin

   LSC.Test.Suite ("SHA2 tests");

   --  FIPS 180-2, Appendix C: SHA-512 Examples

   --  C.1 SHA-512 Example (One-Block Message)
   SHA2_Ctx1 := LSC.SHA2.SHA512_Context_Init;
   Message1 := LSC.SHA2.Block_Type'(0 => 16#6162630000000000#, others => 0);
   LSC.SHA2.Context_Finalize (SHA2_Ctx1, Message1, 24);
   Hash1 := LSC.SHA2.SHA512_Get_Hash (SHA2_Ctx1);

   LSC.Test.Run
     ("SHA-512 Example (One-Block Message)",
      Hash1 =
      LSC.SHA2.SHA512_Hash_Type'(16#DDAF35A193617ABA#,
                                 16#CC417349AE204131#,
                                 16#12E6FA4E89A97EA2#,
                                 16#0A9EEEE64B55D39A#,
                                 16#2192992A274FC1A8#,
                                 16#36BA3C23A3FEEBBD#,
                                 16#454D4423643CE80E#,
                                 16#2A9AC94FA54CA49F#));

   --  C.2 SHA-512 Example (Multi-Block Message)
   SHA2_Ctx2     := LSC.SHA2.SHA512_Context_Init;
   Message2 :=
     LSC.SHA2.Block_Type'
     (16#6162636465666768#,
      16#6263646566676869#,
      16#636465666768696a#,
      16#6465666768696a6b#,
      16#65666768696a6b6c#,
      16#666768696a6b6c6d#,
      16#6768696a6b6c6d6e#,
      16#68696a6b6c6d6e6f#,
      16#696a6b6c6d6e6f70#,
      16#6a6b6c6d6e6f7071#,
      16#6b6c6d6e6f707172#,
      16#6c6d6e6f70717273#,
      16#6d6e6f7071727374#,
      16#6e6f707172737475#,
      16#0000000000000000#,
      16#0000000000000000#);
   LSC.SHA2.Context_Finalize (SHA2_Ctx2, Message2, 896);
   Hash2 := LSC.SHA2.SHA512_Get_Hash (SHA2_Ctx2);

   LSC.Test.Run
     ("SHA-512 Example (Multi-Block Message)",
      Hash2 =
      LSC.SHA2.SHA512_Hash_Type'(16#8e959b75dae313da#,
                                 16#8cf4f72814fc143f#,
                                 16#8f7779c6eb9f7fa1#,
                                 16#7299aeadb6889018#,
                                 16#501d289e4900f7e4#,
                                 16#331b99dec4b5433a#,
                                 16#c7d329eeb6dd2654#,
                                 16#5e96e55b874be909#));

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
      LSC.SHA2.SHA512_Hash_Type'(16#e718483d0ce76964#,
                                 16#4e2e42c7bc15b463#,
                                 16#8e1f98b13b204428#,
                                 16#5632a803afa973eb#,
                                 16#de0ff244877ea60a#,
                                 16#4cb0432ce577c31b#,
                                 16#eb009c5c2c49aa2e#,
                                 16#4eadb217ad8cc09b#));

end SHA2_Tests;
