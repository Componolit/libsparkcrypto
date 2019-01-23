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

with LSC.Types;
with Ada.Unchecked_Conversion;

private with LSC.Internal.SHA256;
private with LSC.Internal.SHA512;

package LSC.SHA2
is
   type Algorithm_Type is (SHA256, SHA384, SHA512);

   function Hash (Algorithm : Algorithm_Type;
                  Message   : LSC.Types.Bytes) return LSC.Types.Bytes;

private

   SHA256_Block_Len : constant := 64;
   subtype SHA256_Block_Type is LSC.Types.Bytes (1 .. SHA256_Block_Len);
   function To_Internal is new Ada.Unchecked_Conversion (SHA256_Block_Type, Internal.SHA256.Block_Type);

   SHA256_Hash_Len : constant := 32;
   subtype SHA256_Hash_Type is LSC.Types.Bytes (1 .. SHA256_Hash_Len);
   function To_Public is new Ada.Unchecked_Conversion (Internal.SHA256.SHA256_Hash_Type, SHA256_Hash_Type);

   SHA384_Hash_Len : constant := 48;
   subtype SHA384_Hash_Type is LSC.Types.Bytes (1 .. SHA384_Hash_Len);
   function To_Public_384 is new Ada.Unchecked_Conversion (Internal.SHA512.SHA384_Hash_Type, SHA384_Hash_Type);

   SHA512_Block_Len : constant := 128;
   subtype SHA512_Block_Type is LSC.Types.Bytes (1 .. SHA512_Block_Len);
   function To_Internal is new Ada.Unchecked_Conversion (SHA512_Block_Type, Internal.SHA512.Block_Type);

   SHA512_Hash_Len : constant := 64;
   subtype SHA512_Hash_Type is LSC.Types.Bytes (1 .. SHA512_Hash_Len);
   function To_Public_512 is new Ada.Unchecked_Conversion (Internal.SHA512.SHA512_Hash_Type, SHA512_Hash_Type);

end LSC.SHA2;
