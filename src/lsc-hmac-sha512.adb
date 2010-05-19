--  This file is part of the sparkcrypto library.
--
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

package body LSC.HMAC.SHA512 is

   IPad : constant SHA2.Block_Type :=
      SHA2.Block_Type'(others => 16#36363636_36363636#);
   OPad : constant SHA2.Block_Type :=
      SHA2.Block_Type'(others => 16#5C5C5C5C_5C5C5C5C#);

   function To_Block (Item : SHA2.Hash_Type) return SHA2.Block_Type is
      Result : SHA2.Block_Type := SHA2.Block_Type'(others => 0);
   begin
      for I in SHA2.Hash_Index
      loop
         Result (I) := Item (I);
         --# assert
         --#    (I in SHA2.Hash_Index) and
         --#    (I in SHA2.Block_Index) and
         --#    (for all Pos in SHA2.Hash_Index range SHA2.Hash_Index'First .. I =>
         --#         (Result (Pos) = Item (Pos)));
      end loop;
      return Result;
   end To_Block;

   function Block_XOR
     (Left  : SHA2.Block_Type;
      Right : SHA2.Block_Type)
      return  SHA2.Block_Type
   is
      Result : SHA2.Block_Type := SHA2.Block_Type'(others => 0);
   begin
      for I in SHA2.Block_Index
      loop
         Result (I) := Left (I) xor Right (I);
         --# assert
         --#    (for all Pos in SHA2.Block_Index range SHA2.Block_Index'First .. I =>
         --#         (Result (Pos) = (Left (Pos) xor Right (Pos))));
      end loop;
      return Result;
   end Block_XOR;

   function Context_Init (Key : SHA2.Block_Type) return Context_Type is
      Result : Context_Type;
   begin
      Debug.Put_Line ("HMAC.SHA512.Context_Init:");

      Result.Key            := Key;
      Result.SHA512_Context := SHA2.Context_Init;
      SHA2.Context_Update
        (Result.SHA512_Context,
         Block_XOR (Result.Key, IPad));
      return Result;
   end Context_Init;

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in SHA2.Block_Type)
   is
   begin
      Debug.Put_Line ("HMAC.SHA512.Context_Update:");
      SHA2.Context_Update (Context.SHA512_Context, Block);
   end Context_Update;

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in SHA2.Block_Type;
      Length  : in SHA2.Block_Length_Type)
   is
      Hash : SHA2.Hash_Type;
   begin
      Debug.Put_Line ("HMAC.SHA512.Context_Finalize:");
      SHA2.Context_Finalize (Context.SHA512_Context, Block, Length);
      Hash := SHA2.Get_Hash (Context.SHA512_Context);

      Context.SHA512_Context := SHA2.Context_Init;
      SHA2.Context_Update
        (Context.SHA512_Context,
         Block_XOR (Context.Key, OPad));
      SHA2.Context_Finalize (Context.SHA512_Context, To_Block (Hash), 512);
   end Context_Finalize;

   function Get_Prf (Context : in Context_Type) return SHA2.Hash_Type is
   begin
      return SHA2.Get_Hash (Context.SHA512_Context);
   end Get_Prf;

   function Get_Auth (Context : in Context_Type) return Auth_Type is
      Result : Auth_Type := Auth_Type'(others => 0);
      Prf    : SHA2.Hash_Type;
   begin
      Prf := SHA2.Get_Hash (Context.SHA512_Context);
      for Index in Auth_Index
      --# assert
      --#    Index in Auth_Index;
      loop
         Result (Index) := Prf (Index);
      end loop;
      return Result;
   end Get_Auth;

end LSC.HMAC.SHA512;
