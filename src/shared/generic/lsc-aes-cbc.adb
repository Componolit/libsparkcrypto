-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2010, Alexander Senier
-- Copyright (C) 2010, secunet Security Networks AG
-- All rights reserved.
--
-- Redistribution  and  use  in  source  and  binary  forms,  with  or  without
-- modification, are permitted provided that the following conditions are met:
--
--    * Redistributions of source code must retain the above copyright notice,
--      this list of conditions and the following disclaimer.
--
--    * Redistributions in binary form must reproduce the above copyright
--      notice, this list of conditions and the following disclaimer in the
--      documentation and/or other materials provided with the distribution.
--
--    * Neither the name of the  nor the names of its contributors may be used
--      to endorse or promote products derived from this software without
--      specific prior written permission.
--
-- THIS SOFTWARE IS PROVIDED BY THE  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-- AND ANY  EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT LIMITED  TO, THE
-- IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
-- ARE  DISCLAIMED. IN  NO EVENT  SHALL  THE COPYRIGHT  HOLDER OR  CONTRIBUTORS
-- BE  LIABLE FOR  ANY  DIRECT, INDIRECT,  INCIDENTAL,  SPECIAL, EXEMPLARY,  OR
-- CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT  LIMITED  TO,  PROCUREMENT  OF
-- SUBSTITUTE GOODS  OR SERVICES; LOSS  OF USE,  DATA, OR PROFITS;  OR BUSINESS
-- INTERRUPTION)  HOWEVER CAUSED  AND ON  ANY THEORY  OF LIABILITY,  WHETHER IN
-- CONTRACT,  STRICT LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE OR  OTHERWISE)
-- ARISING IN ANY WAY  OUT OF THE USE OF THIS SOFTWARE, EVEN  IF ADVISED OF THE
-- POSSIBILITY OF SUCH DAMAGE.
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

      for I in AES.Message_Index range Ciphertext'First .. Ciphertext'Last
      loop

         --# assert
         --#    Length = Length% and
         --#    Plaintext'First = Ciphertext'First and
         --#    Plaintext'Last = Ciphertext'Last and
         --#    Ciphertext'First + Length - 1 <= Plaintext'Last and
         --#    Ciphertext'First + Length - 1 in AES.Message_Index;

         if I <= (Ciphertext'First - 1) + Length then
            Ops32.Block_XOR (Next, Plaintext (I), Temp);
            Next := AES.Encrypt (Context, Temp);

            pragma Warnings (Off, """Ciphertext"" might not be initialized");
            Ciphertext (I) := Next;
            pragma Warnings (On, """Ciphertext"" might not be initialized");
         else
            pragma Warnings (Off, """Ciphertext"" might not be initialized");
            Ciphertext (I) := AES.Null_Block;
            pragma Warnings (On, """Ciphertext"" might not be initialized");
         end if;
      end loop;
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

      for I in AES.Message_Index range Plaintext'First .. Plaintext'Last
      loop
         --# assert
         --#    Length = Length% and
         --#    Plaintext'First = Ciphertext'First and
         --#    Plaintext'Last = Ciphertext'Last and
         --#    Plaintext'First + Length - 1 <= Ciphertext'Last and
         --#    Plaintext'First + Length - 1 in AES.Message_Index;

         if I <= (Plaintext'First - 1) + Length then
            Temp := AES.Decrypt (Context, Ciphertext (I));

            pragma Warnings (Off, """Plaintext"" might not be initialized");
            Ops32.Block_XOR (Temp, Next, Plaintext (I));
            pragma Warnings (On, """Plaintext"" might not be initialized");
            Next := Ciphertext (I);
         else
            pragma Warnings (Off, """Plaintext"" might not be initialized");
            Plaintext (I) := AES.Null_Block;
            pragma Warnings (On, """Plaintext"" might not be initialized");
         end if;
      end loop;
   end Decrypt;
end LSC.AES.CBC;
