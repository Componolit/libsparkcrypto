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
procedure Test_SHA384
is
   Block1, Block2  : LSC.SHA2.Block_Type;
   SHA384_Context1 : OpenSSL.SHA384_Context_Type;
   SHA384_Context2 : LSC.SHA2.Context_Type;
   H1, H2          : LSC.SHA2.SHA384_Hash_Type;
begin
   Block1  := LSC.SHA2.Block_Type'(others => 16#deadbeefcafebabe#);
   Block2  := LSC.SHA2.Block_Type'(others => 16#0000000000636261#);

   S1 := Clock;
   for I in 1 .. 500000
   loop
      OpenSSL.SHA384_Context_Init (SHA384_Context1);
      OpenSSL.SHA384_Context_Update (SHA384_Context1, Block1);
      OpenSSL.SHA384_Context_Finalize (SHA384_Context1, Block2, 56);
   end loop;
   H1 := OpenSSL.SHA384_Get_Hash (SHA384_Context1);
   D1 := Clock - S1;

   S2 := Clock;
   for I in 1 .. 500000
   loop
      SHA384_Context2 := LSC.SHA2.SHA384_Context_Init;
      LSC.SHA2.Context_Update (SHA384_Context2, Block1);
      LSC.SHA2.Context_Finalize (SHA384_Context2, Block2, 56);
   end loop;
   H2 := LSC.SHA2.SHA384_Get_Hash (SHA384_Context2);
   D2 := Clock - S2;

   Result ("     SHA384", H1 = H2, D1, D2);
end Test_SHA384;
