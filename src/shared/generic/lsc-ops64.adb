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

package body LSC.Ops64 is

   function Bytes_To_Word
      (Byte0 : Types.Byte;
       Byte1 : Types.Byte;
       Byte2 : Types.Byte;
       Byte3 : Types.Byte;
       Byte4 : Types.Byte;
       Byte5 : Types.Byte;
       Byte6 : Types.Byte;
       Byte7 : Types.Byte) return Types.Word64
   is
   begin
      return Types.Byte_Array64_To_Word64
          (Types.Byte_Array64_Type'(Byte7, Byte6, Byte5, Byte4,
                                    Byte3, Byte2, Byte1, Byte0));
   end Bytes_To_Word;

   ----------------------------------------------------------------------------

   function XOR2 (V0, V1 : Types.Word64) return Types.Word64
   is
   begin
      return V0 xor V1;
   end XOR2;

   ----------------------------------------------------------------------------

   procedure Block_XOR
     (Left   : in     Types.Word64_Array_Type;
      Right  : in     Types.Word64_Array_Type;
      Result :    out Types.Word64_Array_Type)
   is
   begin
      for I in Types.Index range Result'First .. Result'Last
      loop

         --# check
         --#    I <= Left'Last   and
         --#    I <= Right'Last  and
         --#    I <= Result'Last;

         pragma Warnings (Off, """Result"" might not be initialized");
         Result (I) := XOR2 (Left (I), Right (I));
         pragma Warnings (On, """Result"" might not be initialized");

         --# assert
         --#   (for all Pos in Types.Index range Result'First .. I =>
         --#       (Result (Pos) = XOR2 (Left (Pos), Right (Pos))));

      end loop;
   end Block_XOR;

   ----------------------------------------------------------------------------

   procedure Block_Copy
     (Source : in     Types.Word64_Array_Type;
      Dest   : in out Types.Word64_Array_Type)
   is
   begin

      for I in Types.Index range Source'First .. Source'Last
      loop
         --# check I in Source'Range;

         Dest (I) := Source (I);

         --# assert
         --#    (for all P in Types.Index range Source'First .. I =>
         --#        (Dest (P) = Source (P)));
      end loop;

   end Block_Copy;

end LSC.Ops64;
