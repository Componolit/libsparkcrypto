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

with LSC.AES;
--# inherit
--#    LSC.AES,
--#    LSC.Ops32;

-------------------------------------------------------------------------------
--  References:
--
--  Morris Dworkin, Recommendation for Block Cipher Modes of Operation -
--  Methods and Techniques, NIST Special Publication 800-38A, 2001 Edition
--  National Institute of Standards and Technology, U.S. Department of
--  Commerce, December 2001
-------------------------------------------------------------------------------
package LSC.AES.CBC is

   procedure Encrypt (Context    : in     AES.AES_Enc_Context;
                      IV         : in     AES.Block_Type;
                      Plaintext  : in     AES.Message_Type;
                      Length     : in     AES.Message_Index;
                      Ciphertext :    out AES.Message_Type);
   --# derives
   --#    Ciphertext from Context, IV, Plaintext, Length;
   --# pre
   --#    Plaintext'First = Ciphertext'First and
   --#    Plaintext'Last  = Ciphertext'Last and
   --#    Plaintext'First + Length - 1 in Plaintext'Range and
   --#    Plaintext'First + Length - 1 in AES.Message_Index and
   --#    Ciphertext'First + Length - 1 in Ciphertext'Range and
   --#    Ciphertext'First + Length - 1 in AES.Message_Index;

   procedure Decrypt (Context    : in     AES.AES_Dec_Context;
                      IV         : in     AES.Block_Type;
                      Ciphertext : in     AES.Message_Type;
                      Length     : in     AES.Message_Index;
                      Plaintext  :    out AES.Message_Type);
   --# derives
   --#    Plaintext from Context, IV, Ciphertext, Length;
   --# pre
   --#    Plaintext'First = Ciphertext'First and
   --#    Plaintext'Last  = Ciphertext'Last and
   --#    Plaintext'First + Length - 1 in Plaintext'Range and
   --#    Plaintext'First + Length - 1 in AES.Message_Index and
   --#    Ciphertext'First + Length - 1 in Ciphertext'Range and
   --#    Ciphertext'First + Length - 1 in AES.Message_Index;

end LSC.AES.CBC;
