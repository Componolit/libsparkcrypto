-------------------------------------------------------------------------------
-- This file is part of the sparkcrypto library.
--
-- Copyright (C) 2010  Alexander Senier <mail@senier.net>
-- Copyright (C) 2010  secunet Security Networks AG
--
-- libsparkcrypto is  free software; you  can redistribute it and/or  modify it
-- under  terms of  the GNU  General Public  License as  published by  the Free
-- Software  Foundation;  either version  3,  or  (at  your option)  any  later
-- version.  libsparkcrypto  is  distributed  in  the  hope  that  it  will  be
-- useful,  but WITHOUT  ANY WARRANTY;  without  even the  implied warranty  of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
--
-- As a  special exception under  Section 7 of GPL  version 3, you  are granted
-- additional  permissions  described in  the  GCC  Runtime Library  Exception,
-- version 3.1, as published by the Free Software Foundation.
--
-- You should  have received  a copy of  the GNU General  Public License  and a
-- copy  of  the  GCC  Runtime  Library  Exception  along  with  this  program;
-- see  the  files  COPYING3  and COPYING.RUNTIME  respectively.  If  not,  see
-- <http://www.gnu.org/licenses/>.
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

         -- FIXME: Why is access to Ciphertext'First OK in a loop statement,
         --        but not in this if statement?
         --# accept Flow, 20, Ciphertext, "Accessing Ciphertext'First should be OK";
         if I <= (Ciphertext'First - 1) + Length then
            Ops32.Block_XOR (Next, Plaintext (I), Temp);
            Next := AES.Encrypt (Context, Temp);

            --# accept Flow, 23, Ciphertext, "Initialized in complete loop";
            Ciphertext (I) := Next;
         else
            --# accept Flow, 23, Ciphertext, "Initialized in complete loop";
            Ciphertext (I) := AES.Null_Block;
         end if;
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

      for I in AES.Message_Index range Plaintext'First .. Plaintext'Last
      loop
         --# assert
         --#    Length = Length% and
         --#    Plaintext'First = Ciphertext'First and
         --#    Plaintext'Last = Ciphertext'Last and
         --#    Plaintext'First + Length - 1 <= Ciphertext'Last and
         --#    Plaintext'First + Length - 1 in AES.Message_Index;

         -- FIXME: Why is access to Ciphertext'First OK in a loop statement,
         --        but not in this if statement?
         --# accept Flow, 20, Plaintext, "Accessing Plaintext'First should be OK";
         if I <= (Plaintext'First - 1) + Length then
            Temp := AES.Decrypt (Context, Ciphertext (I));

            --# accept Flow, 23, Plaintext, "Initialized in complete loop";
            Ops32.Block_XOR (Temp, Next, Plaintext (I));
            Next := Ciphertext (I);
         else
            --# accept Flow, 23, Plaintext, "Initialized in complete loop";
            Plaintext (I) := AES.Null_Block;
         end if;
      end loop;

      --# accept Flow, 602, Plaintext, Plaintext, "Initialized in complete loop";
   end Decrypt;
end LSC.AES.CBC;
