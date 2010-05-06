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

with AES256;
--# inherit AES256;

--# main_program;
procedure Main
   --# derives ;
is
   W : AES256.Schedule_Type;
begin
   W := AES256.Key_Expansion (AES256.Key_Type'(16#60_3d_eb_10#,
                                               16#15_ca_71_be#,
                                               16#2b_73_ae_f0#,
                                               16#85_7d_77_81#,
                                               16#1f_35_2c_07#,
                                               16#3b_61_08_d7#,
                                               16#2d_98_10_a3#,
                                               16#09_14_df_f4#));
end Main;
