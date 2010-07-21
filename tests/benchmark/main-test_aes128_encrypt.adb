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
procedure Test_AES128_Encrypt
is
   type Message_Type is array (1 .. 100000) of LSC.AES.Block_Type;

   Plain, Cipher1, Cipher2 : Message_Type;
   Key128                  : LSC.AES.AES128_Key_Type;
   Context1                : OpenSSL.AES_Enc_Context_Type;
   Context2                : LSC.AES.AES_Enc_Context;
begin

   Plain := Message_Type'
      (others => LSC.AES.Block_Type'(16#33221100#,
                                     16#77665544#,
                                     16#bbaa9988#,
                                     16#ffeeddcc#));

   Key128 := LSC.AES.AES128_Key_Type' (16#03020100#,
                                       16#07060504#,
                                       16#0b0a0908#,
                                       16#0f0e0d0c#);

   Context1 := OpenSSL.Create_AES128_Enc_Context (Key128);
   S1 := Clock;
   for k in 1 .. 20
   loop
      for I in Message_Type'Range
      loop
         Cipher1 (I) := OpenSSL.Encrypt (Context1, Plain (I));
      end loop;
   end loop;
   D1 := Clock - S1;

   Context2 := LSC.AES.Create_AES128_Enc_Context (Key128);
   S2 := Clock;
   for k in 1 .. 20
   loop
      for I in Message_Type'Range
      loop
         Cipher2 (I) := LSC.AES.Encrypt (Context2, Plain (I));
      end loop;
   end loop;
   D2 := Clock - S2;

   Result ("AES-128_ENC", Cipher1 = Cipher2, D1, D2);
end;
