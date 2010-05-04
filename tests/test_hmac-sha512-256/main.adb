--  This file is part of the sparkcrypto library.
--
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

with SHA2, HMAC.SHA512, Test, Debug;
use type SHA2.Hash_Type;

--# inherit SHA2, HMAC.SHA512, Test, Debug;

--# main_program;
procedure Main
--# derives ;
is
    Context             : HMAC.SHA512.Context_Type;
    Key                 : SHA2.Block_Type;
    Block               : SHA2.Block_Type;
    PRF_HMAC_SHA_512    : SHA2.Hash_Type;
begin

    --  SHA512 Authentication Test Vectors (RFC 4868, 2.7.2.3.)

    --  Test Case AUTH512-1:

    Key   := SHA2.Block_Type'(others => 16#0b_0b_0b_0b_0b_0b_0b_0b#);
    Block := SHA2.Block_Type'(16#48_69_20_54_68_65_72_65#, others => 0);

    Debug.Put_Line ("HMAC Key:");
    Debug.Print_Block (Key);
    Debug.Put_Line ("HMAC Text:");
    Debug.Print_Block (Block);

    Context := HMAC.SHA512.Context_Init (Key);
    HMAC.SHA512.Context_Finalize (Context, Block, 64);
    PRF_HMAC_SHA_512 := HMAC.SHA512.Get_PRF (Context);

    Test.Run ("AUTH512-1",
              PRF_HMAC_SHA_512 = SHA2.Hash_Type'(16#637edc6e01dce7e6#, 16#742a99451aae82df#,
                                                 16#23da3e92439e590e#, 16#43e761b33e910fb8#,
                                                 16#ac2878ebd5803f6f#, 16#0b61dbce5e251ff8#,
                                                 16#789a4722c1be65ae#, 16#a45fd464e89f8f5b#));
end Main;
