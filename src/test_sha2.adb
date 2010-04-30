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

with SHA2;
--# inherit SHA2;

--# main_program;
procedure Test_SHA2
--# derives ;
is
    Ctx : SHA2.Context_Type;
begin

    --# accept Flow, 10, "Still testing";
    Ctx := SHA2.Context_Init;

    --# accept Flow, 10, Ctx, "Still testing";
    SHA2.Context_Finalize
        (Context => Ctx,
         M       => SHA2.Block_Type'(0 => 16#6162630000000000#, others => 0),
         Length  => 24);

end Test_SHA2;
