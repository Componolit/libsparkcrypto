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
procedure Test_AES128_Decrypt
is
   type Message_Type is array (1 .. 100000) of LSC.AES.Block_Type;

   Plain1, Plain2, Cipher  : Message_Type;
   Key128                  : LSC.AES.AES128_Key_Type;
   Context1                : OpenSSL.AES_Dec_Context_Type;
   Context2                : LSC.AES.AES_Dec_Context;
begin

   Cipher := Message_Type'
      (others => LSC.AES.Block_Type'(16#33221100#,
                                     16#77665544#,
                                     16#bbaa9988#,
                                     16#ffeeddcc#));

   Key128 := LSC.AES.AES128_Key_Type' (16#03020100#,
                                       16#07060504#,
                                       16#0b0a0908#,
                                       16#1f1e1d1c#);

   Context1 := OpenSSL.Create_AES128_Dec_Context (Key128);
   S1 := Clock;
   for k in 1 .. 20
   loop
      for I in Message_Type'Range
      loop
         Plain1 (I) := OpenSSL.Decrypt (Context1, Cipher (I));
      end loop;
   end loop;
   D1 := Clock - S1;

   Context2 := LSC.AES.Create_AES128_Dec_Context (Key128);
   S2 := Clock;
   for k in 1 .. 20
   loop
      for I in Message_Type'Range
      loop
         Plain2 (I) := LSC.AES.Decrypt (Context2, Cipher (I));
      end loop;
   end loop;
   D2 := Clock - S2;

   Result ("AES-128_DEC", Plain1 = Plain2, D1, D2);
end;
