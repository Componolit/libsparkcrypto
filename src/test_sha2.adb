--  Copyright (C) 2010  secunet Security Networks AG
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>
--
--  This program is free software: you can redistribute it and/or modify
--  it under the terms of the GNU General Public License as published by
--  the Free Software Foundation, either version 3 of the License, or
--  (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with this program.  If not, see <http://www.gnu.org/licenses/>.

with SHA2, Debug;
use type SHA2.Hash_Type;

--# inherit SHA2, Debug;

--# main_program;
procedure Test_SHA2
--# derives ;
is
    Ctx1, Ctx2          : SHA2.Context_Type;
    Hash1, Hash2        : SHA2.Hash_Type;
    Message1, Message2  : SHA2.Block_Type;
begin

    Ctx1        := SHA2.Context_Init;
    Message1    := SHA2.Block_Type'(0 => 16#6162630000000000#, others => 0);
    Hash1       := SHA2.Context_Finalize (Ctx1, Message1, 24);

    --# accept Flow, 22, "This is to test the implementation and SHOULD be invariant!";
    if Hash1 /= SHA2.Hash_Type'(16#DDAF35A193617ABA#,
                                16#CC417349AE204131#,
                                16#12E6FA4E89A97EA2#,
                                16#0A9EEEE64B55D39A#,
                                16#2192992A274FC1A8#,
                                16#36BA3C23A3FEEBBD#,
                                16#454D4423643CE80E#,
                                16#2A9AC94FA54CA49F#)
    then
        Debug.Put_Line ("SHA-512 Test #1: FAILED");
    else
        Debug.Put_Line ("SHA-512 Test #1: OK");
    end if;
    --# end accept;

    Ctx2     := SHA2.Context_Init;
    Message2 := SHA2.Block_Type'(16#6162636465666768#,
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
    Hash2 := SHA2.Context_Finalize (Ctx2, Message2, 896);

    --# accept Flow, 22, "This is to test the implementation and SHOULD be invariant!";
    if Hash2 /= SHA2.Hash_Type'(16#8e959b75dae313da#,
                                16#8cf4f72814fc143f#,
                                16#8f7779c6eb9f7fa1#,
                                16#7299aeadb6889018#,
                                16#501d289e4900f7e4#,
                                16#331b99dec4b5433a#,
                                16#c7d329eeb6dd2654#,
                                16#5e96e55b874be909#)
    then
        Debug.Put_Line ("SHA-512 Test #2: FAILED");
    else
        Debug.Put_Line ("SHA-512 Test #2: OK");
    end if;
    --# end accept;

end Test_SHA2;
