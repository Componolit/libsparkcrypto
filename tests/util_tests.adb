-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- @author Alexander Senier
-- @date   2019-01-16
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
with Util;
with LSC.Types;

package body Util_Tests
is
   use type LSC.Types.Bytes;

   procedure Test_Bytes_To_String_Simple (T : in out Test_Cases.Test_Case'Class)
   is
      Result : String := Util.B2S ((16#de#, 16#ad#, 16#be#, 16#ef#));
   begin
      Assert (Result = "deadbeef", "Invalid result: " & Result);
   end Test_Bytes_To_String_Simple;

   ---------------------------------------------------------------------------

   procedure Test_Bytes_To_String_Odd (T : in out Test_Cases.Test_Case'Class)
   is
      Result : String := Util.B2S ((16#c#, 16#af#, 16#ef#, 16#ee#));
   begin
      Assert (Result = "cafefee", "Invalid result: " & Result);
   end Test_Bytes_To_String_Odd;

   ---------------------------------------------------------------------------

   procedure Test_String_To_Bytes_Simple (T : in out Test_Cases.Test_Case'Class)
   is
      Result : LSC.Types.Bytes := Util.S2B ("deadbeef");
   begin
      Assert (Result = (16#de#, 16#ad#, 16#be#, 16#ef#), "Invalid result: " & Util.B2S (Result));
   end Test_String_To_Bytes_Simple;

   ---------------------------------------------------------------------------

   procedure Test_String_To_Bytes_Whitespace (T : in out Test_Cases.Test_Case'Class)
   is
      Result : LSC.Types.Bytes := Util.S2B ("01 23" & ASCII.HT & "45 67 89 ab cd ef");
   begin
      Assert (Result = (16#01#, 16#23#, 16#45#, 16#67#, 16#89#, 16#ab#, 16#cd#, 16#ef#),
              "Invalid result: " & Util.B2S (Result));
   end Test_String_To_Bytes_Whitespace;

   ---------------------------------------------------------------------------

   procedure Test_String_To_Bytes_Odd (T : in out Test_Cases.Test_Case'Class)
   is
      Result : LSC.Types.Bytes := Util.S2B ("dead bee"); -- ;-(
   begin
      Assert (Result = (16#d#, 16#ea#, 16#db#, 16#ee#), "Invalid result: " & Util.B2S (Result));
   end Test_String_To_Bytes_Odd;

   ---------------------------------------------------------------------------

   procedure Test_String_To_Bytes_Surrounding (T : in out Test_Cases.Test_Case'Class)
   is
      Result : LSC.Types.Bytes := Util.S2B ("    0123456789abcdef" & ASCII.HT & " ");
   begin
      Assert (Result = (16#01#, 16#23#, 16#45#, 16#67#, 16#89#, 16#ab#, 16#cd#, 16#ef#),
              "Invalid result: " & Util.B2S (Result));
   end Test_String_To_Bytes_Surrounding;

   ---------------------------------------------------------------------------

   procedure Test_String_To_Bytes_Uppercase (T : in out Test_Cases.Test_Case'Class)
   is
      Result : LSC.Types.Bytes := Util.S2B ("ADF3456789aBCdEf");
   begin
      Assert (Result = (16#ad#, 16#f3#, 16#45#, 16#67#, 16#89#, 16#ab#, 16#cd#, 16#ef#),
              "Invalid result: " & Util.B2S (Result));
   end Test_String_To_Bytes_Uppercase;

   ---------------------------------------------------------------------------

   procedure Invalid_Conversion
   is
      Result : LSC.Types.Bytes := Util.S2B ("An invalid hex string does not belong here!");
   begin
      null;
   end Invalid_Conversion;

   procedure Test_String_To_Bytes_Invalid (T : in out Test_Cases.Test_Case'Class)
   is
   begin
      Assert_Exception (Invalid_Conversion'Access, "Exception expected");
   end Test_String_To_Bytes_Invalid;

   ---------------------------------------------------------------------------

   procedure Register_Tests (T: in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Test_Bytes_To_String_Simple'Access, "Bytes to string (simple)");
      Register_Routine (T, Test_Bytes_To_String_Odd'Access, "Bytes to string (odd)");
      Register_Routine (T, Test_String_To_Bytes_Simple'Access, "String to bytes (simple)");
      Register_Routine (T, Test_String_To_Bytes_Whitespace'Access, "String to bytes (whitespace)");
      Register_Routine (T, Test_String_To_Bytes_Odd'Access, "String to bytes (odd)");
      Register_Routine (T, Test_String_To_Bytes_Surrounding'Access, "String to bytes (surrounding whitespace)");
      Register_Routine (T, Test_String_To_Bytes_Uppercase'Access, "String to bytes (uppercase)");
      Register_Routine (T, Test_String_To_Bytes_Invalid'Access, "String to bytes (invalid)");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("Utils");
   end Name;
end Util_Tests;
