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
   Message1 := LSC.SHA2.Block_Type'(0 => 16#0000000000636261#, others => 0);
   LSC.SHA2.Context_Finalize (SHA2_Ctx1, Message1, 24);
   Hash1 := LSC.SHA2.SHA384_Get_Hash (SHA2_Ctx1);

   LSC.Test.Run
     ("SHA-384 Example (One-Block Message)",
      Hash1 =
      LSC.SHA2.SHA384_Hash_Type'(16#8b5ea3453f7500cb#,
                                 16#0750c69a693da0b5#,
                                 16#63d1de0eab322c27#,
                                 16#ed5bff435a608b1a#,
                                 16#23cce7a12b078680#,
                                 16#a725c834a1ecba58#));

   --  D.2 SHA-384 Example (Multi-Block Message)
   SHA2_Ctx2     := LSC.SHA2.SHA384_Context_Init;
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
   Hash2 := LSC.SHA2.SHA384_Get_Hash (SHA2_Ctx2);

   LSC.Test.Run
     ("SHA-384 Example (Multi-Block Message)",
      Hash2 =
      LSC.SHA2.SHA384_Hash_Type'(16#e84711f7330c3309#,
                                 16#471bcd82c72f193d#,
                                 16#d2053b3b171b1153#,
                                 16#12f7b0e38680a02f#,
                                 16#b92d7e551ac7c7fc#,
                                 16#39607491fae9c366#));

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
      LSC.SHA2.SHA384_Hash_Type'(16#cb74647109180e9d#,
                                 16#1c4a0a314e836e08#,
                                 16#5248f2009c9e14ed#,
                                 16#5b2a4c70c5ce7279#,
                                 16#ebc4ec38dcb3b807#,
                                 16#85893d7fd8dd97ae#));

end SHA384_Tests;
