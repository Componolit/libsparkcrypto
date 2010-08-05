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

with LSC.Ops32;
with LSC.Debug;

package body LSC.HMAC_RIPEMD160 is

   IPad : constant RIPEMD160.Block_Type :=
      RIPEMD160.Block_Type'(others => 16#36363636#);
   OPad : constant RIPEMD160.Block_Type :=
      RIPEMD160.Block_Type'(others => 16#5C5C5C5C#);

   ----------------------------------------------------------------------------

   function To_Block (Item : RIPEMD160.Hash_Type) return RIPEMD160.Block_Type is
      Result : RIPEMD160.Block_Type;
   begin
      for I in RIPEMD160.Block_Index
      --# assert true;
      loop
         --# accept Flow, 23, Result, "Initialized in complete loop";
         if I in RIPEMD160.Hash_Index
         then
            Result (I) := Item (I);
         else
            Result (I) := 0;
         end if;
      end loop;

      --# accept Flow, 602, Result, "Initialized in complete loop";
      return Result;
   end To_Block;

   ----------------------------------------------------------------------------

   function Context_Init (Key : RIPEMD160.Block_Type) return Context_Type is
      Result : Context_Type;
      Temp   : RIPEMD160.Block_Type;
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
      Temp : RIPEMD160.Block_Type;
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

   ----------------------------------------------------------------------------

   function Authenticate
      (Key         : RIPEMD160.Block_Type;
       Message     : RIPEMD160.Message_Type;
       Last_Length : Block_Length_Type) return RIPEMD160.Hash_Type
   is
      HMAC_Ctx     : Context_Type;
   begin

      HMAC_Ctx := Context_Init (Key);

      -- handle all blocks, but the last.
      if Message'Last > Message'First
      then
         for I in RIPEMD160.Message_Index range Message'First .. Message'Last - 1
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

end LSC.HMAC_RIPEMD160;
