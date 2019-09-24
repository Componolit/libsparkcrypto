-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- @author Alexander Senier
-- @date   2019-01-22
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

package LSC.Ops_Generic
is
   pragma Pure;

   -- Perform XOR on two arrays of 8-bit element types
   --
   -- @Left@   - First input array
   -- @Right@  - Second input array
   -- @Result@ - Result array
   generic
      type Left_Index_Type is (<>);
      type Left_Elem_Type is (<>);
      type Left_Data_Type is array (Left_Index_Type range <>) of Left_Elem_Type;
      type Right_Index_Type is (<>);
      type Right_Elem_Type is (<>);
      type Right_Data_Type is array (Right_Index_Type range <>) of Right_Elem_Type;
      type Result_Index_Type is (<>);
      type Result_Elem_Type is (<>);
      type Result_Data_Type is array (Result_Index_Type range <>) of Result_Elem_Type;
   procedure Array_XOR
     (Left   : in     Left_Data_Type;
      Right  : in     Right_Data_Type;
      Result :    out Result_Data_Type)
   with
      Pre =>
        Left'Length = Right'Length and
        Result'Length >= Left'Length;

end LSC.Ops_Generic;
