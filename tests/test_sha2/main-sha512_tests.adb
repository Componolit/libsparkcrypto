-------------------------------------------------------------------------------
--  This file is part of the sparkcrypto library.
--
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>
--  Copyright (C) 2010  secunet Security Networks AG
--
--  This program is free software: you can redistribute it and/or modify it
--  under the terms of the GNU General Public License as published by the Free
--  Software Foundation, either version 3 of the License, or (at your option)
--  any later version.
--
--  This program is distributed in the hope that it will be useful, but WITHOUT
--  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
--  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
--  more details.
--  
--  You should have received a copy of the GNU General Public License along
--  with this program.  If not, see <http://www.gnu.org/licenses/>.
--  
--  As a special exception, if other files instantiate generics from this unit,
--  or you link this unit with other files to produce an executable, this unit
--  does not by itself cause the resulting executable to be covered by the GNU
--  General Public License. This exception does not however invalidate any
--  other reasons why the executable file might be covered by the GNU Public
--  License.
-------------------------------------------------------------------------------

separate (Main)
procedure SHA512_Tests is
   SHA512_Ctx1, SHA512_Ctx2, SHA512_Ctx3  : LSC.SHA512.Context_Type;
   Hash1, Hash2, Hash3              : LSC.SHA512.SHA512_Hash_Type;
   Message1, Message2, Message3     : LSC.SHA512.Block_Type;
begin

   LSC.Test.Suite ("SHA512 tests");

   --  FIPS 180-2, Appendix C: SHA-512 Examples

   --  C.1 SHA-512 Example (One-Block Message)
   SHA512_Ctx1 := LSC.SHA512.SHA512_Context_Init;
   Message1 := LSC.SHA512.Block_Type'(N (16#616263f4aabc124d#),
                                      others => 16#deadc0dedeadbeef#);
   LSC.SHA512.Context_Finalize (SHA512_Ctx1, Message1, 24);
   Hash1 := LSC.SHA512.SHA512_Get_Hash (SHA512_Ctx1);

   LSC.Test.Run
     ("SHA-512 Example (One-Block Message)",
      Hash1 =
      LSC.SHA512.SHA512_Hash_Type'(N (16#ddaf35a193617aba#),
                                   N (16#cc417349ae204131#),
                                   N (16#12e6fa4e89a97ea2#),
                                   N (16#0a9eeee64b55d39a#),
                                   N (16#2192992a274fc1a8#),
                                   N (16#36ba3c23a3feebbd#),
                                   N (16#454d4423643ce80e#),
                                   N (16#2a9ac94fa54ca49f#)));

   --  C.2 SHA-512 Example (Multi-Block Message)
   SHA512_Ctx2     := LSC.SHA512.SHA512_Context_Init;
   Message2 :=
     LSC.SHA512.Block_Type'
     (N (16#6162636465666768#),
      N (16#6263646566676869#),
      N (16#636465666768696a#),
      N (16#6465666768696a6b#),
      N (16#65666768696a6b6c#),
      N (16#666768696a6b6c6d#),
      N (16#6768696a6b6c6d6e#),
      N (16#68696a6b6c6d6e6f#),
      N (16#696a6b6c6d6e6f70#),
      N (16#6a6b6c6d6e6f7071#),
      N (16#6b6c6d6e6f707172#),
      N (16#6c6d6e6f70717273#),
      N (16#6d6e6f7071727374#),
      N (16#6e6f707172737475#),
      N (16#f423ae49fac82234#),
      N (16#deadbeefcafe0000#));
   LSC.SHA512.Context_Finalize (SHA512_Ctx2, Message2, 896);
   Hash2 := LSC.SHA512.SHA512_Get_Hash (SHA512_Ctx2);

   LSC.Test.Run
     ("SHA-512 Example (Multi-Block Message)",
      Hash2 =
      LSC.SHA512.SHA512_Hash_Type'(N (16#8e959b75dae313da#),
                                   N (16#8cf4f72814fc143f#),
                                   N (16#8f7779c6eb9f7fa1#),
                                   N (16#7299aeadb6889018#),
                                   N (16#501d289e4900f7e4#),
                                   N (16#331b99dec4b5433a#),
                                   N (16#c7d329eeb6dd2654#),
                                   N (16#5e96e55b874be909#)));

   --  C.3 SHA-512 Example (Long Message)
   Message3 := LSC.SHA512.Block_Type'(others => N (16#6161616161616161#));

   SHA512_Ctx3 := LSC.SHA512.SHA512_Context_Init;
   for I in Natural range 1 .. 7812
      --#  assert I in Natural;
   loop
      LSC.SHA512.Context_Update (SHA512_Ctx3, Message3);
   end loop;
   LSC.SHA512.Context_Finalize (SHA512_Ctx3, Message3, 512);
   Hash3 := LSC.SHA512.SHA512_Get_Hash (SHA512_Ctx3);

   LSC.Test.Run
     ("SHA-512 Example (Long Message)",
      Hash3 =
      LSC.SHA512.SHA512_Hash_Type'(N (16#e718483d0ce76964#),
                                   N (16#4e2e42c7bc15b463#),
                                   N (16#8e1f98b13b204428#),
                                   N (16#5632a803afa973eb#),
                                   N (16#de0ff244877ea60a#),
                                   N (16#4cb0432ce577c31b#),
                                   N (16#eb009c5c2c49aa2e#),
                                   N (16#4eadb217ad8cc09b#)));

end SHA512_Tests;
