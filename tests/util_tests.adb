-------------------------------------------------------------------------------
--  This file is part of libsparkcrypto.
--
--  @author Alexander Senier
--  @date   2019-01-16
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
with Util;
with LSC.Types;

pragma Style_Checks (Off);

package body Util_Tests
is
   use type LSC.Types.Bytes;
   pragma Warnings (Off, "formal parameter ""T"" is not referenced");

   procedure Test_Bytes_To_String_Simple (T : in out Test_Cases.Test_Case'Class)
   is
      Result : constant String := Util.B2S ((16#de#, 16#ad#, 16#be#, 16#ef#));
   begin
      Assert (Result = "deadbeef", "Invalid result: " & Result);
   end Test_Bytes_To_String_Simple;

   ---------------------------------------------------------------------------

   procedure Test_Bytes_To_String_Odd (T : in out Test_Cases.Test_Case'Class)
   is
      Result : constant String := Util.B2S ((16#c#, 16#af#, 16#ef#, 16#ee#));
   begin
      Assert (Result = "cafefee", "Invalid result: " & Result);
   end Test_Bytes_To_String_Odd;

   ---------------------------------------------------------------------------

   procedure Test_String_To_Bytes_Simple (T : in out Test_Cases.Test_Case'Class)
   is
      Result : constant LSC.Types.Bytes := Util.S2B ("deadbeef");
   begin
      Assert (Result = (16#de#, 16#ad#, 16#be#, 16#ef#), "Invalid result: " & Util.B2S (Result));
   end Test_String_To_Bytes_Simple;

   ---------------------------------------------------------------------------

   procedure Test_String_To_Bytes_Whitespace (T : in out Test_Cases.Test_Case'Class)
   is
      Result : constant LSC.Types.Bytes := Util.S2B ("01 23" & ASCII.HT & "45 67 89 ab cd ef");
   begin
      Assert (Result = (16#01#, 16#23#, 16#45#, 16#67#, 16#89#, 16#ab#, 16#cd#, 16#ef#),
              "Invalid result: " & Util.B2S (Result));
   end Test_String_To_Bytes_Whitespace;

   ---------------------------------------------------------------------------

   procedure Test_String_To_Bytes_Odd (T : in out Test_Cases.Test_Case'Class)
   is
      Result : constant LSC.Types.Bytes := Util.S2B ("dead bee"); -- ;-(
   begin
      Assert (Result = (16#d#, 16#ea#, 16#db#, 16#ee#), "Invalid result: " & Util.B2S (Result));
   end Test_String_To_Bytes_Odd;

   ---------------------------------------------------------------------------

   procedure Test_String_To_Bytes_Surrounding (T : in out Test_Cases.Test_Case'Class)
   is
      Result : constant LSC.Types.Bytes := Util.S2B ("    0123456789abcdef" & ASCII.HT & " ");
   begin
      Assert (Result = (16#01#, 16#23#, 16#45#, 16#67#, 16#89#, 16#ab#, 16#cd#, 16#ef#),
              "Invalid result: " & Util.B2S (Result));
   end Test_String_To_Bytes_Surrounding;

   ---------------------------------------------------------------------------

   procedure Test_String_To_Bytes_Uppercase (T : in out Test_Cases.Test_Case'Class)
   is
      Result : constant LSC.Types.Bytes := Util.S2B ("ADF3456789aBCdEf");
   begin
      Assert (Result = (16#ad#, 16#f3#, 16#45#, 16#67#, 16#89#, 16#ab#, 16#cd#, 16#ef#),
              "Invalid result: " & Util.B2S (Result));
   end Test_String_To_Bytes_Uppercase;

   ---------------------------------------------------------------------------

   procedure Invalid_Conversion
   is
      Result : constant LSC.Types.Bytes := Util.S2B ("An invalid hex string does not belong here!");
      pragma Unreferenced (Result);
   begin
      null;
   end Invalid_Conversion;

   procedure Test_String_To_Bytes_Invalid (T : in out Test_Cases.Test_Case'Class)
   is
   begin
      Assert_Exception (Invalid_Conversion'Access, "Exception expected");
   end Test_String_To_Bytes_Invalid;

   ---------------------------------------------------------------------------

   procedure Test_Text_To_Bytes_Simple (T : in out Test_Cases.Test_Case'Class)
   is
      Result : constant LSC.Types.Bytes := Util.T2B ("Dead Beef!");
   begin
      Assert (Result = (16#44#, 16#65#, 16#61#, 16#64#, 16#20#,
                        16#42#, 16#65#, 16#65#, 16#66#, 16#21#), "Invalid result: " & Util.B2S (Result));
   end Test_Text_To_Bytes_Simple;

   ---------------------------------------------------------------------------

   procedure Test_Bytes_To_Text_Simple (T : in out Test_Cases.Test_Case'Class)
   is
      Result : constant String := Util.B2T ((16#44#, 16#65#, 16#61#, 16#64#, 16#20#,
                                    16#42#, 16#65#, 16#65#, 16#66#, 16#21#));
   begin
      Assert (Result = "Dead Beef!", "Invalid result: " & Result);
   end Test_Bytes_To_Text_Simple;

   ---------------------------------------------------------------------------

   procedure Test_Bytes_To_Text_To_Bytes (T : in out Test_Cases.Test_Case'Class)
   is
      Expected : constant LSC.Types.Bytes :=
         (16#0B#, 16#46#, 16#D9#, 16#8D#, 16#A1#, 16#04#, 16#64#, 16#84#,
          16#60#, 16#55#, 16#8B#, 16#3F#, 16#2B#, 16#22#, 16#4E#, 16#FE#,
          16#CB#, 16#EF#, 16#32#, 16#95#, 16#A7#, 16#0E#, 16#E0#, 16#E9#,
          16#CA#, 16#79#, 16#28#, 16#C9#, 16#8B#, 16#31#, 16#64#, 16#81#,
          16#93#, 16#85#, 16#56#, 16#B2#, 16#28#, 16#22#, 16#A7#, 16#55#,
          16#BA#, 16#4D#, 16#B2#, 16#90#, 16#D3#, 16#E4#, 16#D7#, 16#9F#);
      Result   : constant LSC.Types.Bytes := Util.T2B (Util.B2T (Expected));
   begin
      Assert (Result = Expected, "Invalid result: " & Util.B2S (Result));
   end Test_Bytes_To_Text_To_Bytes;

   ---------------------------------------------------------------------------

   procedure Test_Text_To_Bytes_To_Text (T : in out Test_Cases.Test_Case'Class)
   is
      Expected : constant String :=
         "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do "&
         "eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim " &
         "ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut " &
         "aliquip ex ea commodo consequat. Duis aute irure dolor in";

      Result : constant String := Util.B2T (Util.T2B (Expected));
   begin
      Assert (Result = Expected, "Invalid result: " & Result);
   end Test_Text_To_Bytes_To_Text;

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
      Register_Routine (T, Test_Text_To_Bytes_Simple'Access, "Text to bytes (simple)");
      Register_Routine (T, Test_Bytes_To_Text_Simple'Access, "Bytes to text (simple)");
      Register_Routine (T, Test_Bytes_To_Text_To_Bytes'Access, "Bytes to text to bytes");
      Register_Routine (T, Test_Text_To_Bytes_To_Text'Access, "Text to bytes to text");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("Utils");
   end Name;
end Util_Tests;
