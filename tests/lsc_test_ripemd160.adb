-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
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

with AUnit.Assertions; use AUnit.Assertions;
with Util; use Util;
with LSC.Types;
with LSC.RIPEMD160;
with Ada.Text_IO; use Ada.Text_IO;

use LSC;

package body LSC_Test_RIPEMD160 is

   -- Test vectors from:
   --    RIPEMD-160: A Strengthened Version of RIPEMD , Appendix B: Test values

   procedure Test_RIPEMD160 (Msg : String;
                             MD  : String)
   is
      use type LSC.Types.Bytes;
      Input  : LSC.Types.Bytes := T2B (Msg);
      Result : LSC.Types.Bytes := RIPEMD160.Hash (Input);
   begin
      Assert (Result = S2B (MD), "Invalid hash: " & B2S (Result) & " (expected " & MD & " input len=" & Input'Length'Img & ")");
   end Test_RIPEMD160;

   ---------------------------------------------------------------------------
   -- RIPEMD160
   ---------------------------------------------------------------------------

   RMD_Buffer : String (1 .. 1_000_000);

   procedure Test_RIPEMD160_AB9601 (T : in out Test_Cases.Test_Case'Class)
   is
   begin
      Test_RIPEMD160 ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31");
      Test_RIPEMD160 ("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
      Test_RIPEMD160 ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
      Test_RIPEMD160 ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36");
      Test_RIPEMD160 ("abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
      Test_RIPEMD160 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                      "12a053384a9c0c88e405a06c27dcf49ada62eb2b");
      Test_RIPEMD160 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                      "b0e20b6e3116640286ed3a87a5713079b21f5189");
      Test_RIPEMD160 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                      "9b752e45573d4b39f4dbd3323cab82bf63326bfb");

      RMD_Buffer := (others => 'a');
      Test_RIPEMD160 (RMD_Buffer, "52783243c1697bdbe16d37f97f68f08325dc1528");
	end Test_RIPEMD160_AB9601;

   ---------------------------------------------------------------------------

   procedure Register_Tests (T: in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Test_RIPEMD160_AB9601'Access, "RIPEMD-160 (AB-9601)");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("RIPEMD160");
   end Name;

end LSC_Test_RIPEMD160;
