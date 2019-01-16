package body Util
is
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
   begin
      return (1 => 0);
   end S2B;

end Util;
