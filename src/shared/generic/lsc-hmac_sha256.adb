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

package body LSC.HMAC_SHA256 is

   IPad : constant SHA256.Block_Type :=
      SHA256.Block_Type'(others => 16#36363636#);
   OPad : constant SHA256.Block_Type :=
      SHA256.Block_Type'(others => 16#5C5C5C5C#);

   ----------------------------------------------------------------------------

   function To_Block (Item : SHA256.SHA256_Hash_Type) return SHA256.Block_Type is
      Result : SHA256.Block_Type;
   begin
      for I in SHA256.Block_Index
      --# assert true;
      loop
         --# accept Flow, 23, Result, "Initialized in complete loop";
         if I in SHA256.SHA256_Hash_Index
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

   function Context_Init (Key : SHA256.Block_Type) return Context_Type is
      Result : Context_Type;
      Temp   : SHA256.Block_Type;
   begin
      Debug.Put_Line ("HMAC.SHA256.Context_Init:");

      Result.Key            := Key;
      Result.SHA256_Context := SHA256.SHA256_Context_Init;
      Ops32.Block_XOR (IPad, Result.Key, Temp);
      SHA256.Context_Update (Result.SHA256_Context, Temp);
      return Result;
   end Context_Init;

   ----------------------------------------------------------------------------

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in SHA256.Block_Type)
   is
   begin
      Debug.Put_Line ("HMAC.SHA256.Context_Update:");
      SHA256.Context_Update (Context.SHA256_Context, Block);
   end Context_Update;

   ----------------------------------------------------------------------------

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     SHA256.Block_Type;
      Length  : in     SHA256.Block_Length_Type)
   is
      Hash : SHA256.SHA256_Hash_Type;
      Temp : SHA256.Block_Type;
   begin
      Debug.Put_Line ("HMAC.SHA256.Context_Finalize:");
      SHA256.Context_Finalize (Context.SHA256_Context, Block, Length);
      Hash := SHA256.SHA256_Get_Hash (Context.SHA256_Context);

      Context.SHA256_Context := SHA256.SHA256_Context_Init;
      Ops32.Block_XOR (OPad, Context.Key, Temp);
      SHA256.Context_Update (Context.SHA256_Context, Temp);
      SHA256.Context_Finalize (Context.SHA256_Context, To_Block (Hash), 256);
   end Context_Finalize;

   ----------------------------------------------------------------------------

   function Get_Prf (Context : in Context_Type) return SHA256.SHA256_Hash_Type is
   begin
      return SHA256.SHA256_Get_Hash (Context.SHA256_Context);
   end Get_Prf;

   ----------------------------------------------------------------------------

   function Get_Auth (Context : in Context_Type) return Auth_Type is
      Result : Auth_Type;
      Prf    : SHA256.SHA256_Hash_Type;
   begin
      Prf := SHA256.SHA256_Get_Hash (Context.SHA256_Context);
      for Index in Auth_Index
      --# assert
      --#    (for all I in SHA256.SHA256_Hash_Index => (Prf (I) in Types.Word32)) and
      --#    Index <= Result'Last                                                 and
      --#    Index <= Prf'Last;
      loop
         --# accept Flow, 23, Result, "Initialized in complete loop";
         Result (Index) := Prf (Index);
      end loop;

      --# accept Flow, 602, Result, "Initialized in complete loop";
      return Result;
   end Get_Auth;

   ----------------------------------------------------------------------------

   function Authenticate
      (Key         : SHA256.Block_Type;
       Message     : SHA256.Message_Type;
       Last_Length : Block_Length_Type) return Auth_Type
   is
      HMAC_Ctx     : Context_Type;
   begin

      HMAC_Ctx := Context_Init (Key);

      -- handle all blocks, but the last.
      if Message'Last > Message'First
      then
         for I in SHA256.Message_Index range Message'First .. Message'Last - 1
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
      if Last_Length = Block_Length_Type'Last then

         Context_Update (HMAC_Ctx, Message (Message'Last));
         -- Message (Message'Last) is unused here, as Length is 0.
         Context_Finalize (HMAC_Ctx, Message (Message'Last), 0);
      else
         Context_Finalize (HMAC_Ctx, Message (Message'Last), Last_Length);
      end if;

      return Get_Auth (HMAC_Ctx);
   end Authenticate;

end LSC.HMAC_SHA256;
