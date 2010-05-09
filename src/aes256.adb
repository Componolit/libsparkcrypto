--  This file is part of the sparkcrypto library.

--  Copyright (C) 2010  secunet Security Networks AG
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>

--  This library  is free software:  you can  redistribute it and/or  modify it
--  under the  terms of the GNU  Lesser General Public License  as published by
--  the Free Software Foundation, either version  3 of the License, or (at your
--  option) any later version.

--  This library is distributed in the hope that it will be useful, but WITHOUT
--  ANY  WARRANTY; without  even  the implied  warranty  of MERCHANTABILITY  or
--  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
--  for more details.

--  You should  have received a copy  of the GNU Lesser  General Public License
--  along with this library. If not, see <http://www.gnu.org/licenses/>.

with AES256.Debug;

package body AES256 is

  Sub_Bytes : constant SBox_Type := SBox_Type'
  (16#63#, 16#7c#, 16#77#, 16#7b#, 16#f2#, 16#6b#, 16#6f#, 16#c5#, 16#30#, 16#01#, 16#67#, 16#2b#, 16#fe#, 16#d7#, 16#ab#, 16#76#,
   16#ca#, 16#82#, 16#c9#, 16#7d#, 16#fa#, 16#59#, 16#47#, 16#f0#, 16#ad#, 16#d4#, 16#a2#, 16#af#, 16#9c#, 16#a4#, 16#72#, 16#c0#,
   16#b7#, 16#fd#, 16#93#, 16#26#, 16#36#, 16#3f#, 16#f7#, 16#cc#, 16#34#, 16#a5#, 16#e5#, 16#f1#, 16#71#, 16#d8#, 16#31#, 16#15#,
   16#04#, 16#c7#, 16#23#, 16#c3#, 16#18#, 16#96#, 16#05#, 16#9a#, 16#07#, 16#12#, 16#80#, 16#e2#, 16#eb#, 16#27#, 16#b2#, 16#75#,
   16#09#, 16#83#, 16#2c#, 16#1a#, 16#1b#, 16#6e#, 16#5a#, 16#a0#, 16#52#, 16#3b#, 16#d6#, 16#b3#, 16#29#, 16#e3#, 16#2f#, 16#84#,
   16#53#, 16#d1#, 16#00#, 16#ed#, 16#20#, 16#fc#, 16#b1#, 16#5b#, 16#6a#, 16#cb#, 16#be#, 16#39#, 16#4a#, 16#4c#, 16#58#, 16#cf#,
   16#d0#, 16#ef#, 16#aa#, 16#fb#, 16#43#, 16#4d#, 16#33#, 16#85#, 16#45#, 16#f9#, 16#02#, 16#7f#, 16#50#, 16#3c#, 16#9f#, 16#a8#,
   16#51#, 16#a3#, 16#40#, 16#8f#, 16#92#, 16#9d#, 16#38#, 16#f5#, 16#bc#, 16#b6#, 16#da#, 16#21#, 16#10#, 16#ff#, 16#f3#, 16#d2#,
   16#cd#, 16#0c#, 16#13#, 16#ec#, 16#5f#, 16#97#, 16#44#, 16#17#, 16#c4#, 16#a7#, 16#7e#, 16#3d#, 16#64#, 16#5d#, 16#19#, 16#73#,
   16#60#, 16#81#, 16#4f#, 16#dc#, 16#22#, 16#2a#, 16#90#, 16#88#, 16#46#, 16#ee#, 16#b8#, 16#14#, 16#de#, 16#5e#, 16#0b#, 16#db#,
   16#e0#, 16#32#, 16#3a#, 16#0a#, 16#49#, 16#06#, 16#24#, 16#5c#, 16#c2#, 16#d3#, 16#ac#, 16#62#, 16#91#, 16#95#, 16#e4#, 16#79#,
   16#e7#, 16#c8#, 16#37#, 16#6d#, 16#8d#, 16#d5#, 16#4e#, 16#a9#, 16#6c#, 16#56#, 16#f4#, 16#ea#, 16#65#, 16#7a#, 16#ae#, 16#08#,
   16#ba#, 16#78#, 16#25#, 16#2e#, 16#1c#, 16#a6#, 16#b4#, 16#c6#, 16#e8#, 16#dd#, 16#74#, 16#1f#, 16#4b#, 16#bd#, 16#8b#, 16#8a#,
   16#70#, 16#3e#, 16#b5#, 16#66#, 16#48#, 16#03#, 16#f6#, 16#0e#, 16#61#, 16#35#, 16#57#, 16#b9#, 16#86#, 16#c1#, 16#1d#, 16#9e#,
   16#e1#, 16#f8#, 16#98#, 16#11#, 16#69#, 16#d9#, 16#8e#, 16#94#, 16#9b#, 16#1e#, 16#87#, 16#e9#, 16#ce#, 16#55#, 16#28#, 16#df#,
   16#8c#, 16#a1#, 16#89#, 16#0d#, 16#bf#, 16#e6#, 16#42#, 16#68#, 16#41#, 16#99#, 16#2d#, 16#0f#, 16#b0#, 16#54#, 16#bb#, 16#16#);

   Rcon : constant Rcon_Type := Rcon_Type'
   (16#0100_0000#, 16#0200_0000#, 16#0400_0000#, 16#0800_0000#, 16#1000_0000#, 16#2000_0000#,
    16#4000_0000#, 16#8000_0000#, 16#1b00_0000#, 16#3600_0000#, 16#6c00_0000#, 16#D800_0000#,
    16#Ab00_0000#, 16#4d00_0000#, 16#9a00_0000#, 16#2f00_0000#, 16#5e00_0000#, 16#Bc00_0000#,
    16#6300_0000#, 16#C600_0000#, 16#9700_0000#, 16#3500_0000#, 16#6a00_0000#, 16#D400_0000#,
    16#B300_0000#, 16#7d00_0000#, 16#Fa00_0000#, 16#Ef00_0000#, 16#C500_0000#, 16#9100_0000#);

   ----------------------------------------------------------------------------

   function Sub_Word (Value : Types.Word32) return Types.Word32 is
      Temp : Types.Word8_Array_Type;
   begin
      Temp := Types.Word32_To_Word8_Array (Value);
      return Types.Word8_Array_To_Word32
         (Types.Word8_Array_Type'(Sub_Bytes (Temp (1)),
                                  Sub_Bytes (Temp (2)),
                                  Sub_Bytes (Temp (3)),
                                  Sub_Bytes (Temp (4))));
   end Sub_Word;

   ----------------------------------------------------------------------------

   function Rot_Word (Value : Types.Word32) return Types.Word32 is
   begin
      return Types.ROTL32 (Value, 8);
   end Rot_Word;

   ----------------------------------------------------------------------------

   function Key_Expansion (Key : Key_Type) return Schedule_Type is
      Temp     : Types.Word32;
      Rot_Temp : Types.Word32;
      Sub_Temp : Types.Word32;
      Result   : Schedule_Type := Schedule_Type'(others => 0);
   begin

      for Index in Key_Index
      --# assert Index in Key_Index;
      loop
         Result (Index) := Key (Index);
      end loop;

      LSC.Debug.Put_Line ("Initial schedule:");
      Debug.Print_Schedule (Result);
      LSC.Debug.New_Line;

      for Index in Schedule_Index range Key_Index'Last + 1 .. Schedule_Index'Last
      --# assert Index in Key_Index'Last .. Schedule_Index'Last;
      loop

         Debug.Print_Schedule_Index (Index);
         LSC.Debug.Put (" | ");

         Temp := Result (Index - 1);
         LSC.Debug.Print_Word32 (Temp);
         LSC.Debug.New_Line;

         if Index mod Nk = 0
         then
            Rot_Temp := Rot_Word (Temp);
            Sub_Temp := Sub_Word (Rot_Temp);
            Temp := Sub_Temp xor Rcon (Index/Nk);
         elsif Index mod Nk = 4
         then
            Temp := Sub_Word (Temp);
         end if;
         Result (Index) := Result (Index - 1) xor Temp;

      end loop;

      return Result;

   end Key_Expansion;

   ----------------------------------------------------------------------------

   function Context_Init (Key : Key_Type) return Context
   is
      Result : Context;
   begin
      Result.Schedule := Key_Expansion (Key => Key);
      return Result;
   end Context_Init;

end AES256;
