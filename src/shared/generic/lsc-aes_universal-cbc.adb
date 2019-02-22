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

with LSC.Ops_Universal;

package body LSC.AES_Universal.CBC
is
   -------------
   -- Decrypt --
   -------------

   procedure Decrypt (Ciphertext :     Ciphertext_Type;
                      IV         :     Ciphertext_Type;
                      Key        :     AES_Universal.Dec_Key_Type;
                      Plaintext  : out Plaintext_Type)
   is
      Next : Ciphertext_Type (Ciphertext'Range) := IV;

      procedure Decrypt_XOR is new Ops_Universal.Array_XOR
         (Plaintext_Index_Type, Plaintext_Elem_Type, Plaintext_Type,
          Ciphertext_Index_Type, Ciphertext_Elem_Type, Ciphertext_Type,
          Plaintext_Index_Type, Plaintext_Elem_Type, Plaintext_Type);

      function Decrypt is new AES_Universal.Decrypt
         (Plaintext_Index_Type, Plaintext_Elem_Type, Plaintext_Type,
          Ciphertext_Index_Type, Ciphertext_Elem_Type, Ciphertext_Type);
   begin
      for Offset in 0 .. Ciphertext'Length / 16 - 1
      loop
         declare
            subtype CIT is Ciphertext_Index_Type;
            subtype PIT is Plaintext_Index_Type;
            CT_Start : constant CIT := CIT'Val (CIT'Pos (Ciphertext'First) + 16 * Offset);
            CT_End   : constant CIT := CIT'Val (CIT'Pos (Ciphertext'First) + 16 * Offset + 15);
            PT_Start : constant PIT := PIT'Val (PIT'Pos (Plaintext'First)  + 16 * Offset);
            PT_End   : constant PIT := PIT'Val (PIT'Pos (Plaintext'First)  + 16 * Offset + 15);
         begin
            Decrypt_XOR
               (Left   => Decrypt (Ciphertext (CT_Start .. CT_End), Key),
                Right  => Next,
                Result => Plaintext (PT_Start .. PT_End));
            Next := Ciphertext (CT_Start .. CT_End);
         end;
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

   procedure Encrypt (Plaintext  :     Plaintext_Type;
                      IV         :     Ciphertext_Type;
                      Key        :     AES_Universal.Enc_Key_Type;
                      Ciphertext : out Ciphertext_Type)
   is
      Temp : Plaintext_Type (Plaintext'Range);
      Next : Ciphertext_Type (IV'Range) := IV;

      procedure Encrypt_XOR is new Ops_Universal.Array_XOR
         (Ciphertext_Index_Type, Ciphertext_Elem_Type, Ciphertext_Type,
          Plaintext_Index_Type, Plaintext_Elem_Type, Plaintext_Type,
          Plaintext_Index_Type, Plaintext_Elem_Type, Plaintext_Type);

      function Encrypt is new AES_Universal.Encrypt
         (Plaintext_Index_Type, Plaintext_Elem_Type, Plaintext_Type,
          Ciphertext_Index_Type, Ciphertext_Elem_Type, Ciphertext_Type);
   begin
      for Offset in 0 .. Plaintext'Length / 16 - 1
      loop
         declare
            subtype CIT is Ciphertext_Index_Type;
            subtype PIT is Plaintext_Index_Type;
            CT_Start : constant CIT := CIT'Val (CIT'Pos (Ciphertext'First) + 16 * Offset);
            CT_End   : constant CIT := CIT'Val (CIT'Pos (Ciphertext'First) + 16 * Offset + 15);
            PT_Start : constant PIT := PIT'Val (PIT'Pos (Plaintext'First)  + 16 * Offset);
            PT_End   : constant PIT := PIT'Val (PIT'Pos (Plaintext'First)  + 16 * Offset + 15);
         begin
            Encrypt_XOR
               (Left   => Next,
                Right  => Plaintext (PT_Start .. PT_End),
                Result => Temp);
            Next := Encrypt (Temp, Key);
            Ciphertext (CT_Start .. CT_End) := Next;
         end;
      end loop;

      pragma Annotate (GNATprove, False_Positive,
         """Ciphertext"" might not be initialized",
          "Initialized in complete loop");
   end Encrypt;

   pragma Annotate (GNATprove, False_Positive,
      """Ciphertext"" might not be initialized in ""Encrypt""",
      "Initialized in complete loop");

end LSC.AES_Universal.CBC;
