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

with LSC.AES, LSC.IO, LSC.Byteorder32, LSC.Types, LSC.AES.CBC;
with SPARKUnit;
use type LSC.AES.Block_Type;
use type LSC.AES.Message_Type;

--# inherit
--#    LSC.IO,
--#    LSC.AES,
--#    LSC.Byteorder32,
--#    LSC.Types,
--#    LSC.AES.CBC,
--#    SPARKUnit,
--#    SPARK_IO;

--# main_program;
procedure Main
--# global in out SPARK_IO.Outputs;
--# derives SPARK_IO.Outputs from *;
is
   subtype Harness_Index is Natural range 1 .. 100;
   subtype Harness_Type is SPARKUnit.Harness_Type (Harness_Index);

   Harness        : Harness_Type;

   function N (Item : LSC.Types.Word32) return LSC.Types.Word32
   is
   begin
      return LSC.Byteorder32.BE_To_Native (Item);
   end N;

   procedure AES_Tests
   --# global Harness;
   --# derives Harness from Harness;
   is separate;

   procedure AES_CBC_Tests
   --# global Harness;
   --# derives Harness from Harness;
   is separate;

begin

   SPARKUnit.Create_Harness (Harness, "libsparkcrypto tests");
   AES_Tests;
   AES_CBC_Tests;
   SPARKUnit.Text_Report (Harness);

end Main;
