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

with LSC.Ops32;

package body LSC.AES.CBC is

   procedure Encrypt (Context    : in     AES.AES_Enc_Context;
                      IV         : in     AES.Block_Type;
                      Plaintext  : in     AES.Message_Type;
                      Length     : in     AES.Message_Index;
                      Ciphertext :    out AES.Message_Type)
   is
      Temp : AES.Block_Type;
      Next : AES.Block_Type;
   begin
      Next := IV;
      for I in AES.Message_Index range Ciphertext'First .. Ciphertext'First + Length
      --# assert true;
      loop

         Ops32.Block_XOR (Next, Plaintext (I), Temp);
         Next := AES.Encrypt (Context, Temp);

         --# accept Flow, 23, Ciphertext, "Initialized in complete loop";
         Ciphertext (I) := Next;
      end loop;

      --# accept Flow, 602, Ciphertext, Ciphertext, "Initialized in complete loop";
   end Encrypt;

   ----------------------------------------------------------------------------

   procedure Decrypt (Context    : in     AES.AES_Dec_Context;
                      IV         : in     AES.Block_Type;
                      Ciphertext : in     AES.Message_Type;
                      Length     : in     AES.Message_Index;
                      Plaintext  :    out AES.Message_Type)
   is
      Temp : AES.Block_Type;
      Next : AES.Block_Type;
   begin
      Next := IV;
      for I in AES.Message_Index range Plaintext'First .. Plaintext'First + Length
      --# assert true;
      loop
         Temp := AES.Decrypt (Context, Ciphertext (I));

         --# accept Flow, 23, Plaintext, "Initialized in complete loop";
         Ops32.Block_XOR (Temp, Next, Plaintext (I));
         Next := Ciphertext (I);
      end loop;

      --# accept Flow, 602, Plaintext, Plaintext, "Initialized in complete loop";
   end Decrypt;
end LSC.AES.CBC;
