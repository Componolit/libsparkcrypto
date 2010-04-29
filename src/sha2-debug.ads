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

private package SHA2.Debug is

    procedure Put_Line (T : String);

    procedure Put_T (T : SHA2.Schedule_Index);
    procedure Put_State (S : SHA2.State_Type);
    procedure Put_Hash (H : SHA2.Hash_Type);
    procedure Put_Schedule (S : SHA2.Schedule_Type);

end SHA2.Debug;
