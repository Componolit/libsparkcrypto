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
--  References:
--
--  Morris Dworkin, Recommendation for Block Cipher Modes of Operation -
--  Methods and Techniques, NIST Special Publication 800-38A, 2001 Edition
--  National Institute of Standards and Technology, U.S. Department of
--  Commerce, December 2001
-------------------------------------------------------------------------------

with LSC.AES, LSC.Ops32;
--# inherit LSC.AES,
--#         LSC.Ops32;

package LSC.AES.CBC is

   procedure Encrypt (Context    : in     AES.AES_Enc_Context;
                      IV         : in     AES.Block_Type;
                      Plaintext  : in     AES.Message_Type;
                      Ciphertext :    out AES.Message_Type);
   --# derives
   --#    Ciphertext from Context, IV, Plaintext;
   --# pre
   --#    Plaintext'First = Ciphertext'First and
   --#    Plaintext'Last  = Ciphertext'Last;

   procedure Decrypt (Context    : in     AES.AES_Dec_Context;
                      IV         : in     AES.Block_Type;
                      Ciphertext : in     AES.Message_Type;
                      Plaintext  :    out AES.Message_Type);
   --# derives
   --#    Plaintext from Context, IV, Ciphertext;
   --# pre
   --#    Plaintext'First = Ciphertext'First and
   --#    Plaintext'Last  = Ciphertext'Last;

end LSC.AES.CBC;
