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

package body LSC.AES.CBC is

   procedure Encrypt (Context    : in     AES.AES_Enc_Context;
                      IV         : in     AES.Block_Type;
                      Plaintext  : in     AES.Message_Type;
                      Ciphertext : in out AES.Message_Type)
   is
      Temp : AES.Block_Type := AES.Block_Type'(others => 0);
      Next : AES.Block_Type;
   begin
      Next := IV;
      for I in AES.Message_Index range Plaintext'First .. Plaintext'Last
      --# assert true;
      loop
         Ops.Block_XOR (Next, Plaintext (I), Temp);
         Next := AES.Encrypt (Context, Temp);
         Ciphertext (I) := Next;
      end loop;
   end Encrypt;

   ----------------------------------------------------------------------------

   procedure Decrypt (Context    : in     AES.AES_Dec_Context;
                      IV         : in     AES.Block_Type;
                      Ciphertext : in     AES.Message_Type;
                      Plaintext  : in out AES.Message_Type)
   is
      Temp : AES.Block_Type;
      Next : AES.Block_Type;
   begin
      Next := IV;
      for I in AES.Message_Index range Plaintext'First .. Plaintext'Last
      --# assert true;
      loop
         Temp := AES.Decrypt (Context, Ciphertext (I));
         Ops.Block_XOR (Temp, Next, Plaintext (I));
         Next := Ciphertext (I);
      end loop;
   end Decrypt;
end LSC.AES.CBC;
