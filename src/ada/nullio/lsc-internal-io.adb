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

package body LSC.Internal.IO is

   ----------------------------------------------------------------------------

   procedure Put (T : String) is
   begin
      null;
   end Put;

   ----------------------------------------------------------------------------

   procedure Put_Line (T : String) is
   begin
      null;
   end Put_Line;

   ----------------------------------------------------------------------------

   procedure New_Line is
   begin
      null;
   end New_Line;

   ----------------------------------------------------------------------------

   function Read_Byte return Types.Byte is
   begin
      return 0;
   end Read_Byte;

   ----------------------------------------------------------------------------

   function End_Of_Stream return Boolean is
   begin
      return True;
   end End_Of_Stream;

   ----------------------------------------------------------------------------

   procedure Print_Byte (Item : in Types.Byte) is
   begin
      null;
   end Print_Byte;

   ----------------------------------------------------------------------------

   procedure Print_Word32 (Item : in Types.Word32) is
   begin
      null;
   end Print_Word32;

   ----------------------------------------------------------------------------

   procedure Print_Word64 (Item : in Types.Word64) is
   begin
      null;
   end Print_Word64;

   ----------------------------------------------------------------------------

   procedure Print_Index (I : in Types.Index) is
   begin
      null;
   end Print_Index;

   ----------------------------------------------------------------------------

   procedure Print_Natural (I : Natural) is
   begin
      null;
   end Print_Natural;

   ----------------------------------------------------------------------------

   procedure Print_Word32_Array (Block : in Types.Word32_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean) is
   begin
      null;
   end Print_Word32_Array;

   ----------------------------------------------------------------------------

   procedure Print_Word64_Array (Block : in Types.Word64_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean) is
   begin
      null;
   end Print_Word64_Array;

end LSC.Internal.IO;
