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

package body LSC.HMAC_RIPEMD160 is

   IPad : constant RIPEMD160.Block_Type :=
      RIPEMD160.Block_Type'(others => 16#36363636#);
   OPad : constant RIPEMD160.Block_Type :=
      RIPEMD160.Block_Type'(others => 16#5C5C5C5C#);

   ----------------------------------------------------------------------------

   function To_Block (Item : RIPEMD160.Hash_Type) return RIPEMD160.Block_Type is
      Result : RIPEMD160.Block_Type := RIPEMD160.Block_Type'(others => 0);
   begin
      for I in RIPEMD160.Hash_Index
      loop
         Result (I) := Item (I);
         --# assert
         --#    (I in RIPEMD160.Hash_Index) and
         --#    (I in RIPEMD160.Block_Index) and
         --#    (for all Pos in RIPEMD160.Hash_Index range RIPEMD160.Hash_Index'First .. I =>
         --#         (Result (Pos) = Item (Pos)));
      end loop;
      return Result;
   end To_Block;

   ----------------------------------------------------------------------------

   function Context_Init (Key : RIPEMD160.Block_Type) return Context_Type is
      Result : Context_Type;
      Temp   : RIPEMD160.Block_Type := RIPEMD160.Block_Type'(others => 0);
   begin
      Debug.Put_Line ("HMAC.RIPEMD160.Context_Init:");

      Result.Key            := Key;
      Result.RIPEMD160_Context := RIPEMD160.Context_Init;
      Ops32.Block_XOR (IPad, Result.Key, Temp);
      RIPEMD160.Context_Update (Result.RIPEMD160_Context, Temp);
      return Result;
   end Context_Init;

   ----------------------------------------------------------------------------

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in RIPEMD160.Block_Type)
   is
   begin
      Debug.Put_Line ("HMAC.RIPEMD160.Context_Update:");
      RIPEMD160.Context_Update (Context.RIPEMD160_Context, Block);
   end Context_Update;

   ----------------------------------------------------------------------------

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     RIPEMD160.Block_Type;
      Length  : in     RIPEMD160.Block_Length_Type)
   is
      Hash : RIPEMD160.Hash_Type;
      Temp : RIPEMD160.Block_Type := RIPEMD160.Block_Type'(others => 0);
   begin
      Debug.Put_Line ("HMAC.RIPEMD160.Context_Finalize:");
      RIPEMD160.Context_Finalize (Context.RIPEMD160_Context, Block, Length);
      Hash := RIPEMD160.Get_Hash (Context.RIPEMD160_Context);

      Context.RIPEMD160_Context := RIPEMD160.Context_Init;
      Ops32.Block_XOR (OPad, Context.Key, Temp);
      RIPEMD160.Context_Update (Context.RIPEMD160_Context, Temp);
      RIPEMD160.Context_Finalize (Context.RIPEMD160_Context, To_Block (Hash), 160);
   end Context_Finalize;

   ----------------------------------------------------------------------------

   function Get_Auth (Context : in Context_Type) return RIPEMD160.Hash_Type is
   begin
      return RIPEMD160.Get_Hash (Context.RIPEMD160_Context);
   end Get_Auth;

end LSC.HMAC_RIPEMD160;
