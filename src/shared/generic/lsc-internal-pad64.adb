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

with Interfaces;
with LSC.Internal.Byteorder64;

package body LSC.Internal.Pad64 is

   procedure Block_Terminate
     (Block  : in out Types.Word64_Array_Type;
      Length : in     Types.Word64)
   is
      pragma Inline (Block_Terminate);
      Temp   : Types.Word64;
      Index  : Types.Index;
      Offset : Natural;
   begin

      --  index of partial block
      Index := Block'First + Types.Index (Length / 64);

      --  bit offset within the partial block
      Offset := Natural (63 - Length mod 64);

      Temp := Byteorder64.Native_To_BE (Block (Index));
      Temp := Temp and Interfaces.Shift_Left (not 0, Offset);
      Temp := Temp  or Interfaces.Shift_Left (1, Offset);
      Block (Index) := Byteorder64.BE_To_Native (Temp);

      if Index < Block'Last then
         for I in Types.Index range (Index + 1) .. Block'Last
         loop
            Block (I) := 0;
            pragma Loop_Invariant
              ((for all P in Types.Index range
                  Index + 1 .. I => (Block (P) = 0)) and
               Index = Block'First + Types.Index (Length / 64));
         end loop;
      end if;

   end Block_Terminate;

end LSC.Internal.Pad64;
