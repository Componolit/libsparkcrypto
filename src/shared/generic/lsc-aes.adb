-------------------------------------------------------------------------------
--  This file is part of the sparkcrypto library.
--
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>
--  Copyright (C) 2010  secunet Security Networks AG
--
--  This program is free software: you can redistribute it and/or modify it
--  under the terms of the GNU General Public License as published by the Free
--  Software Foundation, either version 3 of the License, or (at your option)
--  any later version.
--
--  This program is distributed in the hope that it will be useful, but WITHOUT
--  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
--  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
--  more details.
--  
--  You should have received a copy of the GNU General Public License along
--  with this program.  If not, see <http://www.gnu.org/licenses/>.
--  
--  As a special exception, if other files instantiate generics from this unit,
--  or you link this unit with other files to produce an executable, this unit
--  does not by itself cause the resulting executable to be covered by the GNU
--  General Public License. This exception does not however invalidate any
--  other reasons why the executable file might be covered by the GNU Public
--  License.
-------------------------------------------------------------------------------

with LSC.Debug;
with LSC.Ops32;
with LSC.Byteorder32;
with LSC.AES.Tables;
with LSC.AES.Print;

package body LSC.AES is

   ----------------------------------------------------------------------------

   function Sub_Word (Value : Types.Word32) return Types.Word32 is
      Temp : Types.Byte_Array32_Type;
    begin
      Temp := Types.Word32_To_Byte_Array32 (Value);
      return Ops32.Bytes_To_Word (Byte0 => Tables.S (Temp (3)),
                                  Byte1 => Tables.S (Temp (2)),
                                  Byte2 => Tables.S (Temp (1)),
                                  Byte3 => Tables.S (Temp (0)));
   end Sub_Word;

   ----------------------------------------------------------------------------

   function Rot_Word (Value : Types.Word32) return Types.Word32 is
   begin
      return Types.ROTL32 (Value, 8);
   end Rot_Word;

   ----------------------------------------------------------------------------

   function Enc_Key_Expansion (Key : Key_Type;
                               Nk  : Nk_Type;
                               Nr  : Nr_Type) return Schedule_Type
   is
      Temp     : Types.Word32;
      Rot_Temp : Types.Word32;
      Sub_Temp : Types.Word32;
      Result   : Schedule_Type := Schedule_Type'(others => 0);

      procedure Put_Row (I : Types.Word32)
      --# derives null from I;
      is
      begin
         Debug.Put (" ");
         Debug.Print_Word32 (I);
         Debug.Put (" |");
      end Put_Row;

   begin

      for I in Key_Index range Key'First .. Key'Last
      loop
         --# assert I in Schedule_Index;
         Result (I) := Byteorder32.Native_To_BE (Key (I));
      end loop;

      --  DEBUG OUTPUT  -----------------------------------------------------------------------------------------
      Debug.Put_Line ("Initial schedule:");                                                                    --
      Debug.Print_Word32_Array (Result, 1, 4, True);                                                           --
      Debug.New_Line;                                                                                          --
      Debug.Put_Line (" -----+----------+----------+----------+----------+----------+----------+---------- "); --
      Debug.Put_Line ("|  i  |          |  After   |  After   |          |After XOR |          |  w[i] =  |"); --
      Debug.Put_Line ("|(dec)|   temp   |RotWord() |SubWord() |Rcon[i/Nk]|with Rcon | w[i-Nk]  | temp XOR |"); --
      Debug.Put_Line ("|     |          |          |          |          |          |          |  w[i-Nk] |"); --
      Debug.Put_Line (" -----+----------+----------+----------+----------+----------+----------+---------- "); --
      -----------------------------------------------------------------------------------------------------------

      for I in Schedule_Index range Nk .. Nb * (Nr + 1) - 1
      loop

         --# assert I in Schedule_Index;

         --  DEBUG OUTPUT  --------
         Debug.Put ("| ");       --
         Debug.Print_Index (I);  --
         Debug.Put (" |");       --
         --------------------------

         Temp := Result (I - 1);

         --  DEBUG OUTPUT  -
         Put_Row (Temp);  --
         -------------------

         if I mod Nk = 0
         then

            --# assert I mod Nk = 0 and
            --#        I/Nk in Tables.Rcon_Index;

            Rot_Temp := Rot_Word (Temp);
            Sub_Temp := Sub_Word (Rot_Temp);
            Temp     := Ops32.XOR2 (Sub_Temp, Tables.Rcon (I/Nk));

            --  DEBUG OUTPUT  -------------------
            Put_Row (Rot_Temp);                --
            Put_Row (Sub_Temp);                --
            Put_Row (Tables.Rcon (I/Nk));      --
            Put_Row (Temp);                    --
            -------------------------------------

         elsif Nk > 6 and I mod Nk = Nb
         then

            --# assert Nk > 0 and I mod Nk = Nb;

            --  DEBUG OUTPUT  ---------------
            Debug.Put ("          |"); --
            ---------------------------------

            Temp := Sub_Word (Temp);

            --  DEBUG OUTPUT  -----------------------
            Put_Row (Temp);                        --
            Debug.Put ("          |          |");  --
            -----------------------------------------
         else
            --  DEBUG OUTPUT  ---------------------------------------------
            Debug.Put ("          |          |          |          |");  --
            ---------------------------------------------------------------
         end if;

         --# assert I - Nk in Schedule_Index and
         --#        I in Schedule_Index;
         Result (I) := Ops32.XOR2 (Result (I - Nk), Temp);

         --  DEBUG OUTPUT  ------------
         Put_Row (Result (I - Nk));  --
         Put_Row (Result (I));       --
         Debug.New_Line;             --
         ------------------------------

      end loop;

      --  DEBUG OUTPUT  -----------------------------------------------------------------------------------------
      Debug.Put_Line (" -----+----------+----------+----------+----------+----------+----------+---------- "); --
      -----------------------------------------------------------------------------------------------------------

      --  DEBUG OUTPUT  -------------------------------
      Debug.Put_Line ("Final schedule:");            --
      Debug.Print_Word32_Array (Result, 1, 4, True); --
      -------------------------------------------------

      return Result;

   end Enc_Key_Expansion;

   ----------------------------------------------------------------------------

   function Dec_Key_Expansion (Key : Key_Type;
                               Nk  : Nk_Type;
                               Nr  : Nr_Type) return Schedule_Type
   is
      Result : Schedule_Type;
   begin

      Result := Enc_Key_Expansion (Key, Nk, Nr);

      for Round in Schedule_Index range 1 .. Nr - 1
      loop

         --# assert Nb * Round in Schedule_Index;

         Result (Nb * Round) :=
            Ops32.XOR4 (Tables.U1 (Ops32.Byte0 (Result (Nb * Round))),
                        Tables.U2 (Ops32.Byte1 (Result (Nb * Round))),
                        Tables.U3 (Ops32.Byte2 (Result (Nb * Round))),
                        Tables.U4 (Ops32.Byte3 (Result (Nb * Round))));
      end loop;

      for Round in Schedule_Index range 1 .. Nr - 1
      loop

         --# assert Nb * Round + 1 in Schedule_Index;

         Result (Nb * Round + 1) :=
            Ops32.XOR4 (Tables.U1 (Ops32.Byte0 (Result (Nb * Round + 1))),
                        Tables.U2 (Ops32.Byte1 (Result (Nb * Round + 1))),
                        Tables.U3 (Ops32.Byte2 (Result (Nb * Round + 1))),
                        Tables.U4 (Ops32.Byte3 (Result (Nb * Round + 1))));

      end loop;

      for Round in Schedule_Index range 1 .. Nr - 1
      loop

         --# assert Nb * Round + 2 in Schedule_Index;

         Result (Nb * Round + 2) :=
            Ops32.XOR4 (Tables.U1 (Ops32.Byte0 (Result (Nb * Round + 2))),
                        Tables.U2 (Ops32.Byte1 (Result (Nb * Round + 2))),
                        Tables.U3 (Ops32.Byte2 (Result (Nb * Round + 2))),
                        Tables.U4 (Ops32.Byte3 (Result (Nb * Round + 2))));
      end loop;

      for Round in Schedule_Index range 1 .. Nr - 1
      loop

         --# assert Nb * Round + 3 in Schedule_Index;

         Result (Nb * Round + 3) :=
            Ops32.XOR4 (Tables.U1 (Ops32.Byte0 (Result (Nb * Round + 3))),
                        Tables.U2 (Ops32.Byte1 (Result (Nb * Round + 3))),
                        Tables.U3 (Ops32.Byte2 (Result (Nb * Round + 3))),
                        Tables.U4 (Ops32.Byte3 (Result (Nb * Round + 3))));
      end loop;

      --  DEBUG OUTPUT  --------------------------------
      Debug.Put_Line ("Inverse schedule:");           --
      Debug.Print_Word32_Array (Result, 1, 4, True);  --
      --------------------------------------------------

      return Result;

   end Dec_Key_Expansion;

   ----------------------------------------------------------------------------

   function Encrypt (Context   : AES_Enc_Context;
                     Plaintext : Block_Type) return Block_Type
   is
      A0, A1, A2, A3 : Types.Word32;
      C0, C1, C2, C3 : Types.Word32;
   begin

      --  DEBUG  -----------------------------------------------------
      Debug.Put ("PLAINTEXT:   ");                                  --
      Debug.Print_Word32_Array (Plaintext, 1, 8, True);             --
      Debug.New_Line;                                               --
      Debug.New_Line;                                               --
      Print.Print_Round ("input ", Schedule_Index'(0), Plaintext);  --
      ----------------------------------------------------------------

      C0 := Byteorder32.Native_To_BE (Plaintext (0)) xor
            Context.Schedule (0);

      C1 := Byteorder32.Native_To_BE (Plaintext (1)) xor
            Context.Schedule (1);

      C2 := Byteorder32.Native_To_BE (Plaintext (2)) xor
            Context.Schedule (2);

      C3 := Byteorder32.Native_To_BE (Plaintext (3)) xor
            Context.Schedule (3);

      for Round in Schedule_Index range 1 .. Context.Nr - 1
      --# assert
      --#    Round <= Context.Nr - 1               and
      --#    Context = Context%                    and
      --#    Schedule_Index'First <= Nb * Round    and
      --#    Nb * Round + 3 <= Schedule_Index'Last;
      loop

         --  DEBUG  -----------------------------------------
         Print.Print_Round ("start ", Round,               --
                            Block_Type'(C0, C1, C2, C3));  --
         ----------------------------------------------------

         A0 := Ops32.XOR5 (Tables.T1 (Ops32.Byte0 (C0)),
                         Tables.T2 (Ops32.Byte1 (C1)),
                         Tables.T3 (Ops32.Byte2 (C2)),
                         Tables.T4 (Ops32.Byte3 (C3)),
                         Context.Schedule (Nb * Round));

         A1 := Ops32.XOR5 (Tables.T1 (Ops32.Byte0 (C1)),
                         Tables.T2 (Ops32.Byte1 (C2)),
                         Tables.T3 (Ops32.Byte2 (C3)),
                         Tables.T4 (Ops32.Byte3 (C0)),
                         Context.Schedule (Nb * Round + 1));

         A2 := Ops32.XOR5 (Tables.T1 (Ops32.Byte0 (C2)),
                         Tables.T2 (Ops32.Byte1 (C3)),
                         Tables.T3 (Ops32.Byte2 (C0)),
                         Tables.T4 (Ops32.Byte3 (C1)),
                         Context.Schedule (Nb * Round + 2));

         A3 := Ops32.XOR5 (Tables.T1 (Ops32.Byte0 (C3)),
                         Tables.T2 (Ops32.Byte1 (C0)),
                         Tables.T3 (Ops32.Byte2 (C1)),
                         Tables.T4 (Ops32.Byte3 (C2)),
                         Context.Schedule (Nb * Round + 3));

         --# assert
         --#   A0 in Types.Word32                     and
         --#   A1 in Types.Word32                     and
         --#   A2 in Types.Word32                     and
         --#   A3 in Types.Word32                     and
         --#   Round <= Context.Nr - 1                and
         --#   Context = Context%                     and
         --#   Schedule_Index'First <= Nb * Round     and
         --#   Nb * Round + 3 <= Schedule_Index'Last;

         C0 := A0;
         C1 := A1;
         C2 := A2;
         C3 := A3;

      end loop;

      --# assert True;

      --  DEBUG  -----------------------------------------
      Print.Print_Round ("start ", Context.Nr,          --
                         Block_Type'(C0, C1, C2, C3));  --
      ----------------------------------------------------

      A0 := Ops32.Bytes_To_Word
              (Tables.S (Ops32.Byte0 (C0)),
               Tables.S (Ops32.Byte1 (C1)),
               Tables.S (Ops32.Byte2 (C2)),
               Tables.S (Ops32.Byte3 (C3))) xor
            Context.Schedule (Nb * Context.Nr);

      A1 := Ops32.Bytes_To_Word
              (Tables.S (Ops32.Byte0 (C1)),
               Tables.S (Ops32.Byte1 (C2)),
               Tables.S (Ops32.Byte2 (C3)),
               Tables.S (Ops32.Byte3 (C0))) xor
            Context.Schedule (Nb * Context.Nr + 1);

      A2 := Ops32.Bytes_To_Word
              (Tables.S (Ops32.Byte0 (C2)),
               Tables.S (Ops32.Byte1 (C3)),
               Tables.S (Ops32.Byte2 (C0)),
               Tables.S (Ops32.Byte3 (C1))) xor
            Context.Schedule (Nb * Context.Nr + 2);

      A3 := Ops32.Bytes_To_Word
              (Tables.S (Ops32.Byte0 (C3)),
               Tables.S (Ops32.Byte1 (C0)),
               Tables.S (Ops32.Byte2 (C1)),
               Tables.S (Ops32.Byte3 (C2))) xor
            Context.Schedule (Nb * Context.Nr + 3);

      --  DEBUG  -----------------------------------------
      Print.Print_Round ("output", Context.Nr,          --
                         Block_Type'(A0, A1, A2, A3));  --
      ----------------------------------------------------

      return Block_Type'(Byteorder32.BE_To_Native (A0),
                         Byteorder32.BE_To_Native (A1),
                         Byteorder32.BE_To_Native (A2),
                         Byteorder32.BE_To_Native (A3));
   end Encrypt;

   ----------------------------------------------------------------------------

   function Create_AES128_Enc_Context
      (Key : AES128_Key_Type) return AES_Enc_Context
   is
   begin
      return AES_Enc_Context'
         (Schedule => Enc_Key_Expansion (Key => Key,
                                         Nk  => 4,
                                         Nr  => 10),
          Nr       => 10);
   end Create_AES128_Enc_Context;

   ----------------------------------------------------------------------------

   function Create_AES192_Enc_Context
      (Key : AES192_Key_Type) return AES_Enc_Context
   is
   begin
      return AES_Enc_Context'
         (Schedule => Enc_Key_Expansion (Key => Key,
                                         Nk  => 6,
                                         Nr  => 12),
          Nr       => 12);
   end Create_AES192_Enc_Context;

   ----------------------------------------------------------------------------

   function Create_AES256_Enc_Context
      (Key : AES256_Key_Type) return AES_Enc_Context
   is
   begin
      return AES_Enc_Context'
         (Schedule => Enc_Key_Expansion (Key => Key,
                                     Nk  => 8,
                                     Nr  => 14),
          Nr       => 14);
   end Create_AES256_Enc_Context;

   ----------------------------------------------------------------------------

   function Create_AES128_Dec_Context
      (Key : AES128_Key_Type) return AES_Dec_Context
   is
   begin
      return AES_Dec_Context'
         (Schedule => Dec_Key_Expansion (Key => Key,
                                         Nk  => 4,
                                         Nr  => 10),
          Nr       => 10);
   end Create_AES128_Dec_Context;

   ----------------------------------------------------------------------------

   function Create_AES192_Dec_Context
      (Key : AES192_Key_Type) return AES_Dec_Context
   is
   begin
      return AES_Dec_Context'
         (Schedule => Dec_Key_Expansion (Key => Key,
                                         Nk  => 6,
                                         Nr  => 12),
          Nr       => 12);
   end Create_AES192_Dec_Context;

   ----------------------------------------------------------------------------

   function Create_AES256_Dec_Context
      (Key : AES256_Key_Type) return AES_Dec_Context
   is
   begin
      return AES_Dec_Context'
         (Schedule => Dec_Key_Expansion (Key => Key,
                                         Nk  => 8,
                                         Nr  => 14),
          Nr       => 14);
   end Create_AES256_Dec_Context;

   ----------------------------------------------------------------------------

   function Decrypt (Context    : AES_Dec_Context;
                     Ciphertext : Block_Type) return Block_Type
   is
      A0, A1, A2, A3 : Types.Word32;
      C0, C1, C2, C3 : Types.Word32;
   begin

      --  DEBUG  ---------------------------------------------------------------
      Debug.Put ("CIPHERTEXT:  ");                                            --
      Debug.Print_Word32_Array (Ciphertext, 1, 8, True);                      --
      Debug.New_Line;                                                         --
      Print.Print_Round ("iinput", Schedule_Index'(Context.Nr), Ciphertext);  --
      --------------------------------------------------------------------------

      C0 := Byteorder32.Native_To_BE (Ciphertext (0)) xor
            Context.Schedule (Nb * Context.Nr);

      C1 := Byteorder32.Native_To_BE (Ciphertext (1)) xor
            Context.Schedule (Nb * Context.Nr + 1);

      C2 := Byteorder32.Native_To_BE (Ciphertext (2)) xor
            Context.Schedule (Nb * Context.Nr + 2);

      C3 := Byteorder32.Native_To_BE (Ciphertext (3)) xor
            Context.Schedule (Nb * Context.Nr + 3);

      for Round in reverse Schedule_Index range 1 .. Context.Nr - 1
      --# assert
      --#    Round <= Context.Nr - 1               and
      --#    Context = Context%                    and
      --#    Schedule_Index'First <= Nb * Round    and
      --#    Nb * Round + 3 <= Schedule_Index'Last;
      loop

         --  DEBUG  -----------------------------------------
         Print.Print_Round ("istart", Round,               --
                            Block_Type'(C0, C1, C2, C3));  --
         ----------------------------------------------------

         A0 := Ops32.XOR5 (Tables.T5 (Ops32.Byte0 (C0)),
                           Tables.T6 (Ops32.Byte1 (C3)),
                           Tables.T7 (Ops32.Byte2 (C2)),
                           Tables.T8 (Ops32.Byte3 (C1)),
                           Context.Schedule (Nb * Round));

         A1 := Ops32.XOR5 (Tables.T5 (Ops32.Byte0 (C1)),
                           Tables.T6 (Ops32.Byte1 (C0)),
                           Tables.T7 (Ops32.Byte2 (C3)),
                           Tables.T8 (Ops32.Byte3 (C2)),
                           Context.Schedule (Nb * Round + 1));

         A2 := Ops32.XOR5 (Tables.T5 (Ops32.Byte0 (C2)),
                           Tables.T6 (Ops32.Byte1 (C1)),
                           Tables.T7 (Ops32.Byte2 (C0)),
                           Tables.T8 (Ops32.Byte3 (C3)),
                           Context.Schedule (Nb * Round + 2));

         A3 := Ops32.XOR5 (Tables.T5 (Ops32.Byte0 (C3)),
                           Tables.T6 (Ops32.Byte1 (C2)),
                           Tables.T7 (Ops32.Byte2 (C1)),
                           Tables.T8 (Ops32.Byte3 (C0)),
                           Context.Schedule (Nb * Round + 3));

         C0 := A0;
         C1 := A1;
         C2 := A2;
         C3 := A3;

      end loop;

      --# assert True;

      --  DEBUG  -----------------------------------------
      Print.Print_Round ("istart", 0,                   --
                         Block_Type'(C0, C1, C2, C3));  --
      ----------------------------------------------------

      A0 := Ops32.Bytes_To_Word
              (Tables.Si (Ops32.Byte0 (C0)),
               Tables.Si (Ops32.Byte1 (C3)),
               Tables.Si (Ops32.Byte2 (C2)),
               Tables.Si (Ops32.Byte3 (C1))) xor
            Context.Schedule (0);

      A1 := Ops32.Bytes_To_Word
              (Tables.Si (Ops32.Byte0 (C1)),
               Tables.Si (Ops32.Byte1 (C0)),
               Tables.Si (Ops32.Byte2 (C3)),
               Tables.Si (Ops32.Byte3 (C2))) xor
            Context.Schedule (1);

      A2 := Ops32.Bytes_To_Word
              (Tables.Si (Ops32.Byte0 (C2)),
               Tables.Si (Ops32.Byte1 (C1)),
               Tables.Si (Ops32.Byte2 (C0)),
               Tables.Si (Ops32.Byte3 (C3))) xor
            Context.Schedule (2);

      A3 := Ops32.Bytes_To_Word
              (Tables.Si (Ops32.Byte0 (C3)),
               Tables.Si (Ops32.Byte1 (C2)),
               Tables.Si (Ops32.Byte2 (C1)),
               Tables.Si (Ops32.Byte3 (C0))) xor
            Context.Schedule (3);

      --  DEBUG  -----------------------------------------
      Print.Print_Round ("ioutpt", 0,                   --
                         Block_Type'(A0, A1, A2, A3));  --
      ----------------------------------------------------

      return Block_Type'(Byteorder32.BE_To_Native (A0),
                         Byteorder32.BE_To_Native (A1),
                         Byteorder32.BE_To_Native (A2),
                         Byteorder32.BE_To_Native (A3));
   end Decrypt;

end LSC.AES;
