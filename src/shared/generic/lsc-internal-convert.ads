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

with LSC.Internal.AES;
with Ada.Unchecked_Conversion;

generic
   type Index_Type is (<>);
   type Elem_Type is (<>);
   type Byte_Type is array (Index_Type range <>) of Elem_Type;
package LSC.Internal.Convert
is
   subtype Key128_Type is Byte_Type (Index_Type'First .. Index_Type'Val (Index_Type'Pos (Index_Type'First) + 15));
   subtype Key192_Type is Byte_Type (Index_Type'First .. Index_Type'Val (Index_Type'Pos (Index_Type'First) + 23));
   subtype Key256_Type is Byte_Type (Index_Type'First .. Index_Type'Val (Index_Type'Pos (Index_Type'First) + 31));
   subtype Block_Type  is Byte_Type (Index_Type'First .. Index_Type'Val (Index_Type'Pos (Index_Type'First) + 15));

   function K128 is new Ada.Unchecked_Conversion (Key128_Type, Internal.AES.AES128_Key_Type);
   function K192 is new Ada.Unchecked_Conversion (Key192_Type, Internal.AES.AES192_Key_Type);
   function K256 is new Ada.Unchecked_Conversion (Key256_Type, Internal.AES.AES256_Key_Type);
   function To_Internal is new Ada.Unchecked_Conversion (Block_Type, Internal.AES.Block_Type);
   function To_Public is new Ada.Unchecked_Conversion (Internal.AES.Block_Type, Block_Type);

end LSC.Internal.Convert;
