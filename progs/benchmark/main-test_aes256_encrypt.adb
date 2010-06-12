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
procedure Test_AES256_Encrypt
is
   type Message_Type is array (1 .. 100000) of LSC.AES.Block_Type;

   Plain, Cipher1, Cipher2 : Message_Type;
   Key256                  : LSC.AES.AES256_Key_Type;
   Context1                : OpenSSL.AES_Enc_Context_Type;
   Context2                : LSC.AES.AES_Enc_Context;
begin

   Plain := Message_Type'
      (others => LSC.AES.Block_Type'(16#33221100#,
                                     16#77665544#,
                                     16#bbaa9988#,
                                     16#ffeeddcc#));

   Key256 := LSC.AES.AES256_Key_Type' (16#03020100#,
                                       16#07060504#,
                                       16#0b0a0908#,
                                       16#0f0e0d0c#,
                                       16#13121110#,
                                       16#17161514#,
                                       16#1b1a1918#,
                                       16#1f1e1d1c#);

   Context1 := OpenSSL.Create_AES256_Enc_Context (Key256);
   S1 := Clock;
   for k in 1 .. 10
   loop
      for I in Message_Type'Range
      loop
         Cipher1 (I) := OpenSSL.Encrypt (Context1, Plain (I));
      end loop;
   end loop;
   D1 := Clock - S1;

   Context2 := LSC.AES.Create_AES256_Enc_Context (Key256);
   S2 := Clock;
   for k in 1 .. 10
   loop
      for I in Message_Type'Range
      loop
         Cipher2 (I) := LSC.AES.Encrypt (Context2, Plain (I));
      end loop;
   end loop;
   D2 := Clock - S2;

   Result ("AES-256_ENC", Cipher1 = Cipher2, D1, D2);
end;
