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
    Ctx  : SHA2.Context_Type;
    HAsh : SHA2.Hash_Type;
begin

    Ctx := SHA2.Context_Init;

    SHA2.Context_Finalize
        (Context => Ctx,
         M       => SHA2.Block_Type'(0 => 16#6162630000000000#, others => 0),
         Length  => 24,
         Hash    => Hash);

    --# accept Flow, 22, "This is to test the implementation and SHOULD be invariant!";
    if Hash /= SHA2.Hash_Type'(16#DDAF35A193617ABA#,
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


end Test_SHA2;
