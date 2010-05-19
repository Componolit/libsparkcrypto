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

with LSC.AES.Tables, LSC.AES.Print;

package body LSC.AES is

   ----------------------------------------------------------------------------

   function Sub_Word (Value : Types.Word32) return Types.Word32 is
      Temp : Types.Byte_Array_Type;
    begin
      Temp := Types.Word32_To_Byte_Array (Value);
      return Ops.Bytes_To_Word32 (Byte0 => Tables.S (Temp (Types.B0)),
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

   function Key_Expansion (Key : Key_Type;
                           Nk  : Nk_Type) return Schedule_Type is
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
      --# assert I in Key_Index;
      loop
         Result (I) := Key (I);
      end loop;

      --  DEBUG OUTPUT  ---------------------------------------------------------------------------------------------
      Debug.Put_Line ("Initial schedule:");                                                                    --
      Print.Print_Schedule (Result);                                                                               --
      Debug.New_Line;                                                                                          --
      Debug.Put_Line (" -----+----------+----------+----------+----------+----------+----------+---------- "); --
      Debug.Put_Line ("|  i  |          |  After   |  After   |          |After XOR |          |  w[i] =  |"); --
      Debug.Put_Line ("|(dec)|   temp   |RotWord() |SubWord() |Rcon[i/Nk]|with Rcon | w[i-Nk]  | temp XOR |"); --
      Debug.Put_Line ("|     |          |          |          |          |          |          |  w[i-Nk] |"); --
      Debug.Put_Line (" -----+----------+----------+----------+----------+----------+----------+---------- "); --
      ---------------------------------------------------------------------------------------------------------------

      for I in Schedule_Index range Key'Last + 1 .. Schedule_Index'Last
      --# assert
      --#    I in Key'Last + 1 .. Schedule_Index'Last;
      loop

         --  DEBUG OUTPUT  ---------------------
         Debug.Put ("| ");                --
         Print.Print_Schedule_Index (I);  --
         Debug.Put (" |");                --
         ---------------------------------------

         Temp := Result (I - 1);

         Put_Row (Temp);

         if I mod Nk = 0
         then
            Rot_Temp := Rot_Word (Temp);
            Sub_Temp := Sub_Word (Rot_Temp);
            Temp     := Sub_Temp xor Tables.Rcon (I/Nk);

            --  DEBUG OUTPUT  -------------------
            Put_Row (Rot_Temp);                --
            Put_Row (Sub_Temp);                --
            Put_Row (Tables.Rcon (I/Nk));  --
            Put_Row (Temp);                    --
            -------------------------------------

         elsif Nk > 6 and I mod Nk = Nb
         then
            --  DEBUG OUTPUT  ---------------
            Debug.Put ("          |"); --
            ---------------------------------

            Temp := Sub_Word (Temp);

            --  DEBUG OUTPUT  ---------------------------
            Put_Row (Temp);                            --
            Debug.Put ("          |          |");  --
            ---------------------------------------------
         else
            --  DEBUG OUTPUT  -------------------------------------------------
            Debug.Put ("          |          |          |          |");  --
            -------------------------------------------------------------------
         end if;

         Result (I) := Result (I - Nk) xor Temp;

         --  DEBUG OUTPUT  ---------------
         Put_Row (Result (I - Nk));  --
         Put_Row (Result (I));      --
         Debug.New_Line;            --
         ---------------------------------

      end loop;

      --  DEBUG OUTPUT  ---------------------------------------------------------------------------------------------
      Debug.Put_Line (" -----+----------+----------+----------+----------+----------+----------+---------- "); --
      ---------------------------------------------------------------------------------------------------------------

      --  DEBUG OUTPUT  -------------------------
      Debug.Put_Line ("Final schedule:");  --
      Print.Print_Schedule (Result);           --                                                                  --
      -------------------------------------------

      return Result;

   end Key_Expansion;

   ----------------------------------------------------------------------------

   function Encrypt (Context   : AES_Context;
                     Plaintext : Block_Type) return Block_Type
   is
      CT : Block_Type;
   begin

      --  DEBUG  -----------------------------------------------------
      Debug.Put ("PLAINTEXT:   ");                              --
      Print.Print_Block (Plaintext);                                --
      Debug.New_Line;                                           --
      Debug.New_Line;                                           --
      Print.Print_Round ("input ", Schedule_Index'(0), Plaintext);  --
      ----------------------------------------------------------------

      CT := Block_Type'
         (0 => Plaintext (0) xor Context.Schedule (0),
          1 => Plaintext (1) xor Context.Schedule (1),
          2 => Plaintext (2) xor Context.Schedule (2),
          3 => Plaintext (3) xor Context.Schedule (3));

      --  DEBUG  ----------------------------------------------
      Print.Print_Round ("start ", Schedule_Index'(1), CT);  --
      ---------------------------------------------------------

      for Round in Schedule_Index range 1 .. Context.Nr - 1
      --# assert
      --#    Round <= Context.Nr - 1 and
      --#    Context = Context%;
      loop

         CT := Block_Type'
            (0 => (Tables.T1 (Ops.Byte0 (CT (0))) xor
                   Tables.T2 (Ops.Byte1 (CT (1))) xor
                   Tables.T3 (Ops.Byte2 (CT (2))) xor
                   Tables.T4 (Ops.Byte3 (CT (3))) xor
                   Context.Schedule (Nb * Round)),

             1 => (Tables.T1 (Ops.Byte0 (CT (1))) xor
                   Tables.T2 (Ops.Byte1 (CT (2))) xor
                   Tables.T3 (Ops.Byte2 (CT (3))) xor
                   Tables.T4 (Ops.Byte3 (CT (0))) xor
                   Context.Schedule (Nb * Round + 1)),

             2 => (Tables.T1 (Ops.Byte0 (CT (2))) xor
                   Tables.T2 (Ops.Byte1 (CT (3))) xor
                   Tables.T3 (Ops.Byte2 (CT (0))) xor
                   Tables.T4 (Ops.Byte3 (CT (1))) xor
                   Context.Schedule (Nb * Round + 2)),

             3 => (Tables.T1 (Ops.Byte0 (CT (3))) xor
                   Tables.T2 (Ops.Byte1 (CT (0))) xor
                   Tables.T3 (Ops.Byte2 (CT (1))) xor
                   Tables.T4 (Ops.Byte3 (CT (2))) xor
                   Context.Schedule (Nb * Round + 3)));

         --  DEBUG  --------------------------------------
         Print.Print_Round ("start ", Round, CT);  --
         -------------------------------------------------

      end loop;

      CT := Block_Type'
         (0 => Ops.Bytes_To_Word32
                  (Tables.S (Ops.Byte0 (CT (0))),
                   Tables.S (Ops.Byte1 (CT (1))),
                   Tables.S (Ops.Byte2 (CT (2))),
                   Tables.S (Ops.Byte3 (CT (3)))) xor
               Context.Schedule (Nb * Context.Nr),

          1 => Ops.Bytes_To_Word32
                  (Tables.S (Ops.Byte0 (CT (1))),
                   Tables.S (Ops.Byte1 (CT (2))),
                   Tables.S (Ops.Byte2 (CT (3))),
                   Tables.S (Ops.Byte3 (CT (0)))) xor
               Context.Schedule (Nb * Context.Nr + 1),

          2 => Ops.Bytes_To_Word32
                  (Tables.S (Ops.Byte0 (CT (2))),
                   Tables.S (Ops.Byte1 (CT (3))),
                   Tables.S (Ops.Byte2 (CT (0))),
                   Tables.S (Ops.Byte3 (CT (1)))) xor
               Context.Schedule (Nb * Context.Nr + 2),

          3 => Ops.Bytes_To_Word32
                  (Tables.S (Ops.Byte0 (CT (3))),
                   Tables.S (Ops.Byte1 (CT (0))),
                   Tables.S (Ops.Byte2 (CT (1))),
                   Tables.S (Ops.Byte3 (CT (2)))) xor
               Context.Schedule (Nb * Context.Nr + 3));

      --  DEBUG  ------------------------------
      Print.Print_Round ("output", Context.Nr, CT);  --
      -----------------------------------------

      return CT;
   end Encrypt;

   ----------------------------------------------------------------------------

   function Create_AES128_Context (Key : AES128_Key_Type) return AES_Context
   is
   begin
      return AES_Context'(Schedule => Key_Expansion (Key => Key, Nk  => 4),
                          Nr       => 10);
   end Create_AES128_Context;

   ----------------------------------------------------------------------------

   function Create_AES192_Context (Key : AES192_Key_Type) return AES_Context
   is
   begin
      return AES_Context'(Schedule => Key_Expansion (Key => Key, Nk  => 6),
                          Nr       => 12);
   end Create_AES192_Context;

   ----------------------------------------------------------------------------

   function Create_AES256_Context (Key : AES256_Key_Type) return AES_Context
   is
   begin
      return AES_Context'(Schedule => Key_Expansion (Key => Key, Nk  => 8),
                          Nr       => 14);
   end Create_AES256_Context;

end LSC.AES;
