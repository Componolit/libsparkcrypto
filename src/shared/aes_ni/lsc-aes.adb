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

with LSC.Debug;
with LSC.Ops32;
with LSC.AES.Print;
with LSC.AES.Instructions;

package body LSC.AES is

   ----------------------------------------------------------------------------

   function Enc_Key_Expansion (Key : Key_Type;
                               Nk  : Nk_Type;
                               Nr  : Nr_Type) return Schedule_Type
   --# pre
   --#   Key'Length = Nk;
   is
      Temp     : Types.Word32;
      Result   : Schedule_Type := Null_Schedule;
   begin

      for I in Key_Index range Key'First .. Key'Last
      loop
         Result (I) := Key (I);
      end loop;

      --# assert True;

      pragma Debug (LSC.AES.Print.Header (Result));

      for I in Schedule_Index range Nk .. Nb * (Nr + 1) - 1
      loop

         pragma Debug (LSC.AES.Print.Index (I));

         --# assert True;

         Temp := Result (I - 1);

         pragma Debug (LSC.AES.Print.Row (Temp));

         if I mod Nk = 0 then

            --# assert I mod Nk = 0;

            Temp := Instructions.Keygen_Assist (Block_Type'(0, Temp, 0, 0), I / Nk) (1);

            pragma Debug (LSC.AES.Print.Row (Temp));

         elsif Nk > 6 and I mod Nk = Nb then

            --# assert Nk > 0 and I mod Nk = Nb;

            pragma Debug (LSC.AES.Print.Empty (1));

            Temp := Instructions.Keygen_Assist (Block_Type'(0, Temp, 0, 0), 0) (0);

            pragma Debug (LSC.AES.Print.Row (Temp));
            pragma Debug (LSC.AES.Print.Empty (2));
         else
            pragma Debug (LSC.AES.Print.Empty (4));
            null;
         end if;

         --# assert I - Nk in Schedule_Index and
         --#        I in Schedule_Index;
         Result (I) := Ops32.XOR2 (Result (I - Nk), Temp);

         pragma Debug (LSC.AES.Print.Row (Result (I - Nk)));
         pragma Debug (LSC.AES.Print.Row (Result (I)));
         pragma Debug (LSC.Debug.New_Line);

      end loop;

      pragma Debug (LSC.AES.Print.Footer (Result));
      return Result;

   end Enc_Key_Expansion;

   ----------------------------------------------------------------------------

   function Dec_Key_Expansion (Key : Key_Type;
                               Nk  : Nk_Type;
                               Nr  : Nr_Type) return Schedule_Type
   --# pre
   --#   Key'Length = Nk and
   --#   Nk < (Nb * (Nr + 1) - 1);
   is
      Result : Schedule_Type;
      Block : Block_Type;
   begin

      Result := Enc_Key_Expansion (Key, Nk, Nr);

      --# assert True;

      for Round in Schedule_Index range 1 .. Nr - 1
      loop

         --# assert
         --#   Nb * Round in Schedule_Index and
         --#   Nb * Round + 1 in Schedule_Index and
         --#   Nb * Round + 2 in Schedule_Index and
         --#   Nb * Round + 3 in Schedule_Index;

         Block := Instructions.Inv_Mix_Columns
           (Block_Type'
              (Result (Nb * Round),
               Result (Nb * Round + 1),
               Result (Nb * Round + 2),
               Result (Nb * Round + 3)));

         for I in Block_Index
         --# assert True;
         loop
            Result (Nb * Round + I) := Block (I);
         end loop;
      end loop;

      pragma Debug (LSC.AES.Print.Footer (Result));
      return Result;

   end Dec_Key_Expansion;

   ----------------------------------------------------------------------------

   function Encrypt (Context   : AES_Enc_Context;
                     Plaintext : Block_Type) return Block_Type
   is
      Block : Block_Type;
   begin

      pragma Debug (AES.Print.Block ("PLAINTEXT:   ", "input ", Plaintext, Schedule_Index'(0)));

      for I in Block_Index
      --# assert True;
      loop
         --# accept Flow, 23, Block, "Initialized in complete loop";
         Block (I) := Plaintext (I) xor Context.Schedule (I);
      end loop;

      --# assert True;

      for Round in Schedule_Index range 1 .. Context.Nr - 1
      --# assert
      --#    Round <= Context.Nr - 1               and
      --#    Context = Context%                    and
      --#    Schedule_Index'First <= Nb * Round    and
      --#    Nb * Round + 3 <= Schedule_Index'Last;
      loop

         pragma Debug (Print.Print_Round ("start ", Round, Block));

         Block := Instructions.Encrypt
           (Block,
            Block_Type'
              (Context.Schedule (Nb * Round),
               Context.Schedule (Nb * Round + 1),
               Context.Schedule (Nb * Round + 2),
               Context.Schedule (Nb * Round + 3)));

         --# assert
         --#   Round <= Context.Nr - 1                and
         --#   Context = Context%                     and
         --#   Schedule_Index'First <= Nb * Round     and
         --#   Nb * Round + 3 <= Schedule_Index'Last;
      end loop;

      --# assert True;

      pragma Debug (Print.Print_Round ("start ", Context.Nr, Block));

      Block := Instructions.Encrypt_Last
        (Block,
         Block_Type'
           (Context.Schedule (Nb * Context.Nr),
            Context.Schedule (Nb * Context.Nr + 1),
            Context.Schedule (Nb * Context.Nr + 2),
            Context.Schedule (Nb * Context.Nr + 3)));

      --# assert True;

      --# accept Flow, 602, Block, "Initialized in complete loop";

      return Block;
   end Encrypt;

   ----------------------------------------------------------------------------

   function Create_AES128_Enc_Context
      (Key : AES128_Key_Type) return AES_Enc_Context
   is
   begin
      return AES_Enc_Context'
         (Schedule => Enc_Key_Expansion (Key => Key,
                                         Nk  => 4,
                                         Nr  => 10),
          Nr       => 10);
   end Create_AES128_Enc_Context;

   ----------------------------------------------------------------------------

   function Create_AES192_Enc_Context
      (Key : AES192_Key_Type) return AES_Enc_Context
   is
   begin
      return AES_Enc_Context'
         (Schedule => Enc_Key_Expansion (Key => Key,
                                         Nk  => 6,
                                         Nr  => 12),
          Nr       => 12);
   end Create_AES192_Enc_Context;

   ----------------------------------------------------------------------------

   function Create_AES256_Enc_Context
      (Key : AES256_Key_Type) return AES_Enc_Context
   is
   begin
      return AES_Enc_Context'
         (Schedule => Enc_Key_Expansion (Key => Key,
                                     Nk  => 8,
                                     Nr  => 14),
          Nr       => 14);
   end Create_AES256_Enc_Context;

   ----------------------------------------------------------------------------

   function Create_AES128_Dec_Context
      (Key : AES128_Key_Type) return AES_Dec_Context
   is
   begin
      return AES_Dec_Context'
         (Schedule => Dec_Key_Expansion (Key => Key,
                                         Nk  => 4,
                                         Nr  => 10),
          Nr       => 10);
   end Create_AES128_Dec_Context;

   ----------------------------------------------------------------------------

   function Create_AES192_Dec_Context
      (Key : AES192_Key_Type) return AES_Dec_Context
   is
   begin
      return AES_Dec_Context'
         (Schedule => Dec_Key_Expansion (Key => Key,
                                         Nk  => 6,
                                         Nr  => 12),
          Nr       => 12);
   end Create_AES192_Dec_Context;

   ----------------------------------------------------------------------------

   function Create_AES256_Dec_Context
      (Key : AES256_Key_Type) return AES_Dec_Context
   is
   begin
      return AES_Dec_Context'
         (Schedule => Dec_Key_Expansion (Key => Key,
                                         Nk  => 8,
                                         Nr  => 14),
          Nr       => 14);
   end Create_AES256_Dec_Context;

   ----------------------------------------------------------------------------

   function Decrypt (Context    : AES_Dec_Context;
                     Ciphertext : Block_Type) return Block_Type
   is
      Block : Block_Type;
   begin

      pragma Debug (AES.Print.Block ("CIPHERTEXT:  ", "iinput", Ciphertext, Schedule_Index'(Context.Nr)));

      for I in Block_Index
      --# assert True;
      loop
         --# accept Flow, 23, Block, "Initialized in complete loop";
         Block (I) := Ciphertext (I) xor
           Context.Schedule (Nb * Context.Nr + I);
      end loop;

      for Round in reverse Schedule_Index range 1 .. Context.Nr - 1
      --# assert
      --#    Round <= Context.Nr - 1               and
      --#    Context = Context%                    and
      --#    Schedule_Index'First <= Nb * Round    and
      --#    Nb * Round + 3 <= Schedule_Index'Last;
      loop

         pragma Debug (Print.Print_Round ("istart", Round, Block));

         Block := Instructions.Decrypt
           (Block,
            Block_Type'
              (Context.Schedule (Nb * Round),
               Context.Schedule (Nb * Round + 1),
               Context.Schedule (Nb * Round + 2),
               Context.Schedule (Nb * Round + 3)));
      end loop;

      --# assert True;

      pragma Debug (Print.Print_Round ("istart", 0, Block));

      Block := Instructions.Decrypt_Last
        (Block,
         Block_Type'
           (Context.Schedule (0),
            Context.Schedule (1),
            Context.Schedule (2),
            Context.Schedule (3)));

      --# assert True;

      pragma Debug (Print.Print_Round ("ioutpt", 0, Block));

      --# accept Flow, 602, Block, "Initialized in complete loop";

      return Block;
   end Decrypt;

end LSC.AES;
