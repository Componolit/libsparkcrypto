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

package body LSC.HMAC_SHA384 is

   IPad : constant SHA512.Block_Type :=
      SHA512.Block_Type'(others => 16#36363636_36363636#);
   OPad : constant SHA512.Block_Type :=
      SHA512.Block_Type'(others => 16#5C5C5C5C_5C5C5C5C#);

   ----------------------------------------------------------------------------

   function To_Block (Item : SHA512.SHA384_Hash_Type) return SHA512.Block_Type is
      Result : SHA512.Block_Type := SHA512.Block_Type'(others => 0);
   begin
      for I in SHA512.SHA384_Hash_Index
      loop
         Result (I) := Item (I);
         --# assert
         --#    (I in SHA512.SHA384_Hash_Index) and
         --#    (I in SHA512.Block_Index) and
         --#    (for all Pos in SHA512.SHA384_Hash_Index range SHA512.SHA384_Hash_Index'First .. I =>
         --#         (Result (Pos) = Item (Pos)));
      end loop;
      return Result;
   end To_Block;

   ----------------------------------------------------------------------------

   function Context_Init (Key : SHA512.Block_Type) return Context_Type is
      Result : Context_Type;
      Temp   : SHA512.Block_Type;
   begin
      Debug.Put_Line ("HMAC.SHA384.Context_Init:");

      Result.Key            := Key;
      Result.SHA384_Context := SHA512.SHA384_Context_Init;
      Ops64.Block_XOR (IPad, Result.Key, Temp);
      SHA512.Context_Update (Result.SHA384_Context, Temp);
      return Result;
   end Context_Init;

   ----------------------------------------------------------------------------

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in SHA512.Block_Type)
   is
   begin
      Debug.Put_Line ("HMAC.SHA384.Context_Update:");
      SHA512.Context_Update (Context.SHA384_Context, Block);
   end Context_Update;

   ----------------------------------------------------------------------------

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     SHA512.Block_Type;
      Length  : in     SHA512.Block_Length_Type)
   is
      Hash : SHA512.SHA384_Hash_Type;
      Temp : SHA512.Block_Type;
   begin
      Debug.Put_Line ("HMAC.SHA384.Context_Finalize:");
      SHA512.Context_Finalize (Context.SHA384_Context, Block, Length);
      Hash := SHA512.SHA384_Get_Hash (Context.SHA384_Context);

      Context.SHA384_Context := SHA512.SHA384_Context_Init;
      Ops64.Block_XOR (OPad, Context.Key, Temp);
      SHA512.Context_Update (Context.SHA384_Context, Temp);
      SHA512.Context_Finalize (Context.SHA384_Context, To_Block (Hash), 384);
   end Context_Finalize;

   ----------------------------------------------------------------------------

   function Get_Prf (Context : in Context_Type) return SHA512.SHA384_Hash_Type is
   begin
      return SHA512.SHA384_Get_Hash (Context.SHA384_Context);
   end Get_Prf;

   ----------------------------------------------------------------------------

   function Get_Auth (Context : in Context_Type) return Auth_Type is
      Result : Auth_Type := Auth_Type'(others => 0);
      Prf    : SHA512.SHA384_Hash_Type;
   begin
      Prf := SHA512.SHA384_Get_Hash (Context.SHA384_Context);
      for Index in Auth_Index
      --# assert
      --#    Index in Auth_Index;
      loop
         Result (Index) := Prf (Index);
      end loop;
      return Result;
   end Get_Auth;

   ----------------------------------------------------------------------------

   function Authenticate
      (Key         : SHA512.Block_Type;
       Message     : SHA512.Message_Type;
       Last_Length : Block_Length_Type) return Auth_Type
   is
      HMAC_Ctx     : Context_Type;
   begin

      HMAC_Ctx := Context_Init (Key);

      -- handle all blocks, but the last.
      if Message'First > Message'Last
      then
         for I in SHA512.Message_Index range Message'First .. Message'Last - 1
         loop
            --# assert
            --#    Message'First > Message'Last and
            --#    I <= Message'Last;
            Context_Update (HMAC_Ctx, Message (I));
         end loop;
      end if;

      --  If the last block of the message is a full block (i.e. Last_Length is
      --  Block_Length_Type'Last) then we have to pass it to Context_Update and
      --  call Context_Finalize with a length of 0 (on a dummy block)
      --  afterwards.
      if Last_Length = Block_Length_Type'Last then Context_Update (HMAC_Ctx,
         Message (Message'Last));

         -- Message (Message'Last) is unused here, as Length is 0.
         Context_Finalize (HMAC_Ctx, Message (Message'Last), 0);
      else
         Context_Finalize (HMAC_Ctx, Message (Message'Last), Last_Length);
      end if;

      return Get_Auth (HMAC_Ctx);
   end Authenticate;

end LSC.HMAC_SHA384;
