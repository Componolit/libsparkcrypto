package body Util
is
   Invalid_Input_Data : exception;

   ---------
   -- B2S --
   ---------

   function B2S (Data : LSC.Types.Bytes) return String
   is
      use type LSC.Types.Byte;

      B, Nibble : LSC.Types.Byte;

      function Hex_Digit (D : LSC.Types.Byte) return Character is
      (case D is
         when 16#0# => '0', when 16#1# => '1', when 16#2# => '2', when 16#3# => '3',
         when 16#4# => '4', when 16#5# => '5', when 16#6# => '6', when 16#7# => '7',
         when 16#8# => '8', when 16#9# => '9', when 16#A# => 'a', when 16#b# => 'b',
         when 16#c# => 'c', when 16#d# => 'd', when 16#e# => 'e', when 16#f# => 'f',
         when others => '*');

      Leading_Zero  : Boolean := True;
      Result_Offset : Natural := 0;
   begin
      for D of Data
      loop
         Result_Offset := Result_Offset + (if D = 0 then 2 elsif D <= 16#f# then 1 else 0);
         exit when D > 16#f#;
      end loop;

      return Result : String (Result_Offset + 1 .. 2 * Data'Length)
      do
         for I in Result'Range
         loop
            B := Data (Data'First + (I + 1) / 2 - 1);
            Nibble := (if I mod 2 = 0
                       then B and LSC.Types.Byte (16#f#)
                       else B  /  LSC.Types.Byte (16#10#));

            Result (I) := Hex_Digit (Nibble);
         end loop;
      end return;
   end B2S;

   ---------
   -- S2B --
   ---------

   function S2B (Data : String) return LSC.Types.Bytes
   is
      function To_Byte (C : Character) return LSC.Types.Byte is
      (case C is
         when '0' => 16#0#, when '1' => 16#1#, when '2' => 16#2#, when '3' => 16#3#,
         when '4' => 16#4#, when '5' => 16#5#, when '6' => 16#6#, when '7' => 16#7#,
         when '8' => 16#8#, when '9' => 16#9#, when 'a' => 16#a#, when 'b' => 16#b#,
         when 'c' => 16#c#, when 'd' => 16#d#, when 'e' => 16#e#, when 'f' => 16#f#,
         when 'A' => 16#a#, when 'B' => 16#b#, when 'C' => 16#c#, when 'D' => 16#d#,
         when 'E' => 16#e#, when 'F' => 16#f#,
         when others => 16#ff#);

      function Is_Whitespace (C : Character) return Boolean is
      (case C is
         when ' '      => True,
         when ASCII.HT => True,
         when others   => False);

      Position     : Natural := 1;
      Num_Nibbles  : Natural := 0;
      Nibble       : LSC.Types.Byte;
      High_Nibble  : Boolean;
      Previous     : LSC.Types.Byte := 0;

      use type LSC.Types.Byte;
   begin
      for C of Data
      loop
         if To_Byte (C) <= 16#f#
         then
            Num_Nibbles := Num_Nibbles + 1;
         end if;
      end loop;

      return Result : LSC.Types.Bytes (1 .. (Num_Nibbles + 1)/ 2)
      do
         High_Nibble := Num_Nibbles mod 2 = 0;

         for C of Data
         loop

            if not Is_Whitespace (C)
            then
               Nibble := To_Byte (C);
               if Nibble > 16#f#
               then
                  raise Invalid_Input_Data with ">>>" & Data & "<<<";
               end if;

               if High_Nibble
               then
                  Previous := 16#10# * Nibble;
               else
                  Result (Position) := Previous + Nibble;
                  Position := Position + 1;
               end if;
               High_Nibble := not High_Nibble;

            end if;
         end loop;
      end return;
   end S2B;

end Util;
