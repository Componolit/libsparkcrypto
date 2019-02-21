-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- @author Alexander Senier
-- @date   2019-01-21
--
-- Copyright (C) 2018 Componolit GmbH
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

package body LSC.AES.CBC
is
   -------------
   -- Decrypt --
   -------------

   procedure Decrypt (Ciphertext :     LSC.Types.Bytes;
                      IV         :     LSC.Types.Bytes;
                      Key        :     AES.Dec_Key_Type;
                      Plaintext  : out LSC.Types.Bytes)
   is
      CT_Offset : Types.Natural_Index;
      PT_Offset : Types.Natural_Index;
      Next : LSC.Types.Bytes (1 .. 16) := IV;
   begin
      for Offset in 0 .. Ciphertext'Length / 16 - 1
      loop
         CT_Offset := Ciphertext'First + Offset * 16;
         PT_Offset := Plaintext'First + Offset * 16;
         Types.Bytes_XOR
            (Left   => AES.Decrypt (Ciphertext (CT_Offset .. CT_Offset + 15), Key),
             Right  => Next,
             Result => Plaintext (PT_Offset .. PT_Offset + 15));
         Next := Ciphertext (CT_Offset .. CT_Offset + 15);
      end loop;

      pragma Annotate (GNATprove, False_Positive,
         """Plaintext"" might not be initialized",
         "Initialized in complete loop");
   end Decrypt;

   pragma Annotate (GNATprove, False_Positive,
      """Plaintext"" might not be initialized in ""Decrypt""",
      "Initialized in complete loop");

   -------------
   -- Encrypt --
   -------------

   procedure Encrypt (Plaintext  :     LSC.Types.Bytes;
                      IV         :     LSC.Types.Bytes;
                      Key        :     AES.Enc_Key_Type;
                      Ciphertext : out LSC.Types.Bytes)
   is
      CT_Offset : Types.Natural_Index;
      PT_Offset : Types.Natural_Index;
      Temp : LSC.Types.Bytes (1 .. 16);
      Next : LSC.Types.Bytes (1 .. 16) := IV;
   begin
      for Offset in 0 .. Plaintext'Length / 16 - 1
      loop
         CT_Offset := Ciphertext'First + Offset * 16;
         PT_Offset := Plaintext'First + Offset * 16;
         Types.Bytes_XOR
            (Left   => Next,
             Right  => Plaintext (PT_Offset .. PT_Offset + 15),
             Result => Temp);
         Next := AES.Encrypt (Temp, Key);
         Ciphertext (CT_Offset .. CT_Offset + 15) := Next;
      end loop;

      pragma Annotate (GNATprove, False_Positive,
         """Ciphertext"" might not be initialized",
          "Initialized in complete loop");
   end Encrypt;

   pragma Annotate (GNATprove, False_Positive,
      """Ciphertext"" might not be initialized in ""Encrypt""",
      "Initialized in complete loop");

end LSC.AES.CBC;
