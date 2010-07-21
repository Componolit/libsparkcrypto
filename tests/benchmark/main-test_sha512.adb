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
procedure Test_SHA512
is
   Block1, Block2  : LSC.SHA512.Block_Type;
   SHA512_Context1 : OpenSSL.SHA512_Context_Type;
   SHA512_Context2 : LSC.SHA512.Context_Type;
   H1, H2          : LSC.SHA512.SHA512_Hash_Type;
begin
   Block1  := LSC.SHA512.Block_Type'(others => 16#deadbeefcafebabe#);
   Block2  := LSC.SHA512.Block_Type'(others => 16#0000000000636261#);

   S1 := Clock;
   for I in 1 .. 500000
   loop
      OpenSSL.SHA512_Context_Init (SHA512_Context1);
      OpenSSL.SHA512_Context_Update (SHA512_Context1, Block1);
      OpenSSL.SHA512_Context_Finalize (SHA512_Context1, Block2, 56);
   end loop;
   H1 := OpenSSL.SHA512_Get_Hash (SHA512_Context1);
   D1 := Clock - S1;

   S2 := Clock;
   for I in 1 .. 500000
   loop
      SHA512_Context2 := LSC.SHA512.SHA512_Context_Init;
      LSC.SHA512.Context_Update (SHA512_Context2, Block1);
      LSC.SHA512.Context_Finalize (SHA512_Context2, Block2, 56);
   end loop;
   H2 := LSC.SHA512.SHA512_Get_Hash (SHA512_Context2);
   D2 := Clock - S2;

   Result ("     SHA512", H1 = H2, D1, D2);
end Test_SHA512;
