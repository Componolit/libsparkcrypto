-------------------------------------------------------------------------------
--  This file is part of libsparkcrypto.
--
--  Copyright (C) 2018 Componolit GmbH
--  All rights reserved.
--
--  Redistribution  and  use  in  source  and  binary  forms,  with  or  without
--  modification, are permitted provided that the following conditions are met:
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
--  THIS SOFTWARE IS PROVIDED BY THE  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
--  AND ANY  EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT LIMITED  TO, THE
--  IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
--  ARE  DISCLAIMED. IN  NO EVENT  SHALL  THE COPYRIGHT  HOLDER OR  CONTRIBUTORS
--  BE  LIABLE FOR  ANY  DIRECT, INDIRECT,  INCIDENTAL,  SPECIAL, EXEMPLARY,  OR
--  CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT  LIMITED  TO,  PROCUREMENT  OF
--  SUBSTITUTE GOODS  OR SERVICES; LOSS  OF USE,  DATA, OR PROFITS;  OR BUSINESS
--  INTERRUPTION)  HOWEVER CAUSED  AND ON  ANY THEORY  OF LIABILITY,  WHETHER IN
--  CONTRACT,  STRICT LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE OR  OTHERWISE)
--  ARISING IN ANY WAY  OUT OF THE USE OF THIS SOFTWARE, EVEN  IF ADVISED OF THE
--  POSSIBILITY OF SUCH DAMAGE.
-------------------------------------------------------------------------------

with AUnit.Assertions; use AUnit.Assertions;
with Util; use Util;
with LSC.RIPEMD160.HMAC;
with LSC.Types;

pragma Style_Checks ("-s");
pragma Warnings (Off, "formal parameter ""T"" is not referenced");

package body LSC_Test_HMAC_RIPEMD160 is

   procedure Test_HMAC (Key     : String;
                        Msg     : String;
                        Mac     : String;
                        Textkey : Boolean := False;
                        Textmsg : Boolean := False)
   is
      use type LSC.Types.Bytes;

      Converted_Key : constant LSC.Types.Bytes := (if Textkey then T2B (Key) else S2B (Key));
      Converted_Msg : constant LSC.Types.Bytes := (if Textmsg then T2B (Msg) else S2B (Msg));
      Converted_Mac : constant LSC.Types.Bytes := S2B (Mac);

      Result : constant LSC.Types.Bytes :=
         LSC.RIPEMD160.HMAC.HMAC (Key     => Converted_Key,
                                  Message => Converted_Msg,
                                  Length  => Converted_Mac'Length);
   begin
      Assert (Result = Converted_Mac, "Invalid HMAC: got " & B2S (Result) & ", expected " & Mac);
   end Test_HMAC;

   ---------------------------------------------------------------------------
   --  RFC 2202 Test vectors
   ---------------------------------------------------------------------------

   procedure Test_HMAC_RFC (T : in out Test_Cases.Test_Case'Class)
   is
   begin
      Test_HMAC (Key => "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                 Msg => "Hi There",
                 Mac => "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668",
                 Textmsg => True);
      Test_HMAC (Key => "Jefe",
                 Msg => "what do ya want for nothing?",
                 Mac => "dda6c0213a485a9e24f4742064a7f033b43c4069",
                 Textmsg => True, Textkey => True);
      Test_HMAC (Key => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                 Msg => "dddddddddddddddddddddddddddddddddddddddddddddddddd" &
                        "dddddddddddddddddddddddddddddddddddddddddddddddddd",
                 Mac => "b0b105360de759960ab4f35298e116e295d8e7c1");
      Test_HMAC (Key => "0102030405060708090a0b0c0d0e0f10111213141516171819",
                 Msg => "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" &
                        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                 Mac => "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4");
      Test_HMAC (Key => "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                 Msg => "Test With Truncation",
                 Mac => "7619693978f91d90539ae786500ff3d8e0518e39",
                 Textmsg => True);
      Test_HMAC (Key => "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                 Msg => "Test With Truncation",
                 Mac => "7619693978f91d90539ae786",
                 Textmsg => True);
      Test_HMAC (Key => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                 Msg => "Test Using Larger Than Block-Size Key - Hash Key First",
                 Mac => "6466ca07ac5eac29e1bd523e5ada7605b791fd8b",
                 Textmsg => True);
      Test_HMAC (Key => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                 Msg => "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
                 Mac => "69ea60798d71616cce5fd0871e23754cd75d5a0a",
                 Textmsg => True);
   end Test_HMAC_RFC;

   ---------------------------------------------------------------------------

   procedure Register_Tests (T : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Test_HMAC_RFC'Access, "HMAC RIPEMD-160 (RFC 2202)");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("HMAC RIPEMD160");
   end Name;

end LSC_Test_HMAC_RIPEMD160;
