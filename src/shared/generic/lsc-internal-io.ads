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

with LSC.Internal.Types;
use type LSC.Internal.Types.Index;

-------------------------------------------------------------------------------
-- Input/Output operations
-------------------------------------------------------------------------------
package LSC.Internal.IO is

   pragma Pure;

   -- Output string @T@
   procedure Put (T : String)
     with Depends => (null => T);

   -- Output string @T@ followed by a line terminator
   procedure Put_Line (T : String)
     with Depends => (null => T);

   -- Start a new line
   procedure New_Line
     with Depends => null;

   -- Read one byte from input
   function Read_Byte return Types.Byte;

   -- True if End_Of_Stream is reached
   function End_Of_Stream return Boolean;

   -- Output byte @Item@
   procedure Print_Byte (Item : in Types.Byte)
     with Depends => (null => Item);

   -- Output 32-bit word @Item@
   procedure Print_Word32 (Item : in Types.Word32)
     with Depends => (null => Item);

   -- Output 64-bit word @Item@
   procedure Print_Word64 (Item : in Types.Word64)
     with Depends => (null => Item);

   -- Output index @I@
   procedure Print_Index (I : in Types.Index)
     with Depends => (null => I);

   -- Output natural number @I@
   procedure Print_Natural (I : in Natural)
     with Depends => (null => I);

   -- Output @Block@, an array of 32-bit words
   --
   -- @Space@ - Number of spaces to separate Word32 values <br>
   -- @Break@ - Insert a line terminator after @Break@ Word32 values <br>
   -- @Newln@ - Insert a line terminator after printing all Word32 values <br>
   --
   procedure Print_Word32_Array (Block : in Types.Word32_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean)
     with
       Depends => (null => (Block, Space, Break, Newln)),
       Pre =>
         Break > 0;

   -- Output @Block@, an array of 64-bit words
   --
   -- @Space@ - Number of spaces to separate Word64 values <br>
   -- @Break@ - Insert a line terminator after @Break@ Word64 values <br>
   -- @Newln@ - Insert a line terminator after printing all Word64 values <br>
   --
   procedure Print_Word64_Array (Block : in Types.Word64_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean)
     with
       Depends => (null => (Block, Space, Break, Newln)),
       Pre =>
         Break > 0;

end LSC.Internal.IO;
