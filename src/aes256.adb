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

with AES256.Tables, AES256.Debug;

package body AES256 is

   ----------------------------------------------------------------------------

   function Sub_Word (Value : Types.Word32) return Types.Word32 is
      Temp : Types.Byte_Array_Type;
    begin
      Temp := Types.Word32_To_Byte_Array (Value);
      return Types.Bytes_To_Word32 (Byte0 => Tables.S (Temp (Types.B0)),
                                    Byte1 => Tables.S (Temp (Types.B1)),
                                    Byte2 => Tables.S (Temp (Types.B2)),
                                    Byte3 => Tables.S (Temp (Types.B3)));
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

      procedure Put_Row (I : Types.Word32)
      --# derives null from I;
      is
      begin
         LSC.Debug.Put (" ");
         LSC.Debug.Print_Word32 (I);
         LSC.Debug.Put (" |");
      end Put_Row;

   begin

      for Index in Key_Index
      --# assert Index in Key_Index;
      loop
         Result (Index) := Key (Index);
      end loop;

      --  DEBUG OUTPUT  ---------------------------------------------------------------------------------------------
      LSC.Debug.Put_Line ("Initial schedule:");                                                                    --
      Debug.Print_Schedule (Result);                                                                               --
      LSC.Debug.New_Line;                                                                                          --
      LSC.Debug.Put_Line (" -----+----------+----------+----------+----------+----------+----------+---------- "); --
      LSC.Debug.Put_Line ("|  i  |          |  After   |  After   |          |After XOR |          |  w[i] =  |"); --
      LSC.Debug.Put_Line ("|(dec)|   temp   |RotWord() |SubWord() |Rcon[i/Nk]|with Rcon | w[i-Nk]  | temp XOR |"); --
      LSC.Debug.Put_Line ("|     |          |          |          |          |          |          |  w[i-Nk] |"); --
      LSC.Debug.Put_Line (" -----+----------+----------+----------+----------+----------+----------+---------- "); --
      ---------------------------------------------------------------------------------------------------------------

      for Index in Schedule_Index range Key_Index'Last + 1 .. Schedule_Index'Last
      --# assert
      --#    Index in Key_Index'Last + 1 .. Schedule_Index'Last;
      loop

         --  DEBUG OUTPUT  ---------------------
         LSC.Debug.Put ("| ");                --
         Debug.Print_Schedule_Index (Index);  --
         LSC.Debug.Put (" |");                --
         ---------------------------------------

         Temp := Result (Index - 1);

         Put_Row (Temp);

         if Index mod Nk = 0
         then
            Rot_Temp := Rot_Word (Temp);
            Sub_Temp := Sub_Word (Rot_Temp);
            Temp     := Sub_Temp xor Tables.Rcon (Index/Nk);

            --  DEBUG OUTPUT  -------------------
            Put_Row (Rot_Temp);                --
            Put_Row (Sub_Temp);                --
            Put_Row (Tables.Rcon (Index/Nk));  --
            Put_Row (Temp);                    --
            -------------------------------------

         elsif Nk > 6 and Index mod Nk = Nb
         then
            --  DEBUG OUTPUT  ---------------
            LSC.Debug.Put ("          |"); --
            ---------------------------------

            Temp := Sub_Word (Temp);

            --  DEBUG OUTPUT  ---------------------------
            Put_Row (Temp);                            --
            LSC.Debug.Put ("          |          |");  --
            ---------------------------------------------
         else
            --  DEBUG OUTPUT  -------------------------------------------------
            LSC.Debug.Put ("          |          |          |          |");  --
            -------------------------------------------------------------------
         end if;

         Result (Index) := Result (Index - Nk) xor Temp;

         --  DEBUG OUTPUT  ---------------
         Put_Row (Result (Index - Nk));  --
         Put_Row (Result (Index));      --
         LSC.Debug.New_Line;            --
         ---------------------------------

      end loop;

      --  DEBUG OUTPUT  ---------------------------------------------------------------------------------------------
      LSC.Debug.Put_Line (" -----+----------+----------+----------+----------+----------+----------+---------- "); --
      ---------------------------------------------------------------------------------------------------------------

      --  DEBUG OUTPUT  -------------------------
      LSC.Debug.Put_Line ("Final schedule:");  --
      Debug.Print_Schedule (Result);           --                                                                  --
      -------------------------------------------

      return Result;

   end Key_Expansion;

   ----------------------------------------------------------------------------

   function Encrypt (Key       : Key_Type;
                     Plaintext : Block_Type) return Block_Type
   is
      Schedule : Schedule_Type;
      CT       : Block_Type;
   begin

      Schedule := Key_Expansion (Key);

      --  DEBUG  -----------------------------------------------------
      LSC.Debug.Put ("PLAINTEXT:   ");                              --
      Debug.Print_Block (Plaintext);                                --
      LSC.Debug.New_Line;                                           --
      LSC.Debug.Put ("KEY:         ");                              --
      Debug.Print_Key (Key);                                        --
      LSC.Debug.New_Line;                                           --
      LSC.Debug.New_Line;                                           --
      Debug.Print_Round ("input ", Schedule_Index'(0), Plaintext);  --
      ----------------------------------------------------------------

      CT := Block_Type'
         (0 => Plaintext (0) xor Schedule (0),
          1 => Plaintext (1) xor Schedule (1),
          2 => Plaintext (2) xor Schedule (2),
          3 => Plaintext (3) xor Schedule (3));

      --  DEBUG  ----------------------------------------------
      Debug.Print_Round ("start ", Schedule_Index'(1), CT);  --
      ---------------------------------------------------------

      for Round in Schedule_Index range 1 .. Nr - 1
      --# assert Round in Schedule_Index;
      loop

         CT := Block_Type'
            (0 => (Tables.T1 (Types.Byte0 (CT (0))) xor
                   Tables.T2 (Types.Byte1 (CT (1))) xor
                   Tables.T3 (Types.Byte2 (CT (2))) xor
                   Tables.T4 (Types.Byte3 (CT (3))) xor
                   Schedule (Nb * Round)),

             1 => (Tables.T1 (Types.Byte0 (CT (1))) xor
                   Tables.T2 (Types.Byte1 (CT (2))) xor
                   Tables.T3 (Types.Byte2 (CT (3))) xor
                   Tables.T4 (Types.Byte3 (CT (0))) xor
                   Schedule (Nb * Round + 1)),

             2 => (Tables.T1 (Types.Byte0 (CT (2))) xor
                   Tables.T2 (Types.Byte1 (CT (3))) xor
                   Tables.T3 (Types.Byte2 (CT (0))) xor
                   Tables.T4 (Types.Byte3 (CT (1))) xor
                   Schedule (Nb * Round + 2)),

             3 => (Tables.T1 (Types.Byte0 (CT (3))) xor
                   Tables.T2 (Types.Byte1 (CT (0))) xor
                   Tables.T3 (Types.Byte2 (CT (1))) xor
                   Tables.T4 (Types.Byte3 (CT (2))) xor
                   Schedule (Nb * Round + 3)));

         --  DEBUG  --------------------------------------
         Debug.Print_Round ("start ", Round, CT);  --
         -------------------------------------------------

      end loop;

      CT := Block_Type'
         (0 => Types.Bytes_To_Word32
                  (Tables.S (Types.Byte0 (CT (0))),
                   Tables.S (Types.Byte1 (CT (1))),
                   Tables.S (Types.Byte2 (CT (2))),
                   Tables.S (Types.Byte3 (CT (3)))) xor
               Schedule (Nb * Nr),

          1 => Types.Bytes_To_Word32
                  (Tables.S (Types.Byte0 (CT (1))),
                   Tables.S (Types.Byte1 (CT (2))),
                   Tables.S (Types.Byte2 (CT (3))),
                   Tables.S (Types.Byte3 (CT (0)))) xor
               Schedule (Nb * Nr + 1),

          2 => Types.Bytes_To_Word32
                  (Tables.S (Types.Byte0 (CT (2))),
                   Tables.S (Types.Byte1 (CT (3))),
                   Tables.S (Types.Byte2 (CT (0))),
                   Tables.S (Types.Byte3 (CT (1)))) xor
               Schedule (Nb * Nr + 2),

          3 => Types.Bytes_To_Word32
                  (Tables.S (Types.Byte0 (CT (3))),
                   Tables.S (Types.Byte1 (CT (0))),
                   Tables.S (Types.Byte2 (CT (1))),
                   Tables.S (Types.Byte3 (CT (2)))) xor
               Schedule (Nb * Nr + 3));

      --  DEBUG  ------------------------------
      Debug.Print_Round ("output", Nr, CT);  --
      -----------------------------------------

      return CT;
   end Encrypt;

   ----------------------------------------------------------------------------

end AES256;
