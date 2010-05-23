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
procedure SHA384_Tests is
   SHA2_Ctx1, SHA2_Ctx2, SHA2_Ctx3  : LSC.SHA2.Context_Type;
   Hash1, Hash2, Hash3              : LSC.SHA2.SHA384_Hash_Type;
   Message1, Message2, Message3     : LSC.SHA2.Block_Type;
begin

   LSC.Test.Suite ("SHA384 tests");

   --  FIPS 180-2, Appendix C: SHA-384 Examples

   --  D.1 SHA-384 Example (One-Block Message)
   SHA2_Ctx1 := LSC.SHA2.SHA384_Context_Init;
   Message1 := LSC.SHA2.Block_Type'(0 => 16#6162630000000000#, others => 0);
   LSC.SHA2.Context_Finalize (SHA2_Ctx1, Message1, 24);
   Hash1 := LSC.SHA2.SHA384_Get_Hash (SHA2_Ctx1);

   LSC.Test.Run
     ("SHA-384 Example (One-Block Message)",
      Hash1 =
      LSC.SHA2.SHA384_Hash_Type'(16#cb00753f45a35e8b#,
                                 16#b5a03d699ac65007#,
                                 16#272c32ab0eded163#,
                                 16#1a8b605a43ff5bed#,
                                 16#8086072ba1e7cc23#,
                                 16#58baeca134c825a7#));

   --  D.2 SHA-384 Example (Multi-Block Message)
   SHA2_Ctx2     := LSC.SHA2.SHA384_Context_Init;
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
   Hash2 := LSC.SHA2.SHA384_Get_Hash (SHA2_Ctx2);

   LSC.Test.Run
     ("SHA-384 Example (Multi-Block Message)",
      Hash2 =
      LSC.SHA2.SHA384_Hash_Type'(16#09330c33f71147e8#,
                                 16#3d192fc782cd1b47#,
                                 16#53111b173b3b05d2#,
                                 16#2fa08086e3b0f712#,
                                 16#fcc7c71a557e2db9#,
                                 16#66c3e9fa91746039#));

   --  D.3 SHA-384 Example (Long Message)
   Message3 := LSC.SHA2.Block_Type'(others => 16#61_61_61_61_61_61_61_61#);

   SHA2_Ctx3 := LSC.SHA2.SHA384_Context_Init;
   for I in Natural range 1 .. 7812
      --#  assert I in Natural;
   loop
      LSC.SHA2.Context_Update (SHA2_Ctx3, Message3);
   end loop;
   LSC.SHA2.Context_Finalize (SHA2_Ctx3, Message3, 512);
   Hash3 := LSC.SHA2.SHA384_Get_Hash (SHA2_Ctx3);

   LSC.Test.Run
     ("SHA-384 Example (Long Message)",
      Hash3 =
      LSC.SHA2.SHA384_Hash_Type'(16#9d0e1809716474cb#,
                                 16#086e834e310a4a1c#,
                                 16#ed149e9c00f24852#,
                                 16#7972cec5704c2a5b#,
                                 16#07b8b3dc38ecc4eb#,
                                 16#ae97ddd87f3d8985#));

end SHA384_Tests;
