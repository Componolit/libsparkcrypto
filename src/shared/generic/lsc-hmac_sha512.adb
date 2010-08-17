-------------------------------------------------------------------------------
-- This file is part of the sparkcrypto library.
--
-- Copyright (C) 2010  Alexander Senier <mail@senier.net>
-- Copyright (C) 2010  secunet Security Networks AG
--
-- libsparkcrypto is  free software; you  can redistribute it and/or  modify it
-- under  terms of  the GNU  General Public  License as  published by  the Free
-- Software  Foundation;  either version  3,  or  (at  your option)  any  later
-- version.  libsparkcrypto  is  distributed  in  the  hope  that  it  will  be
-- useful,  but WITHOUT  ANY WARRANTY;  without  even the  implied warranty  of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
--
-- As a  special exception under  Section 7 of GPL  version 3, you  are granted
-- additional  permissions  described in  the  GCC  Runtime Library  Exception,
-- version 3.1, as published by the Free Software Foundation.
--
-- You should  have received  a copy of  the GNU General  Public License  and a
-- copy  of  the  GCC  Runtime  Library  Exception  along  with  this  program;
-- see  the  files  COPYING3  and COPYING.RUNTIME  respectively.  If  not,  see
-- <http://www.gnu.org/licenses/>.
-------------------------------------------------------------------------------

with LSC.Debug, LSC.Ops64;

package body LSC.HMAC_SHA512 is

   IPad : constant SHA512.Block_Type :=
      SHA512.Block_Type'(others => 16#36363636_36363636#);
   OPad : constant SHA512.Block_Type :=
      SHA512.Block_Type'(others => 16#5C5C5C5C_5C5C5C5C#);

   ----------------------------------------------------------------------------

   function To_Block (Item : SHA512.SHA512_Hash_Type) return SHA512.Block_Type
   --# return Result =>
   --#     (for all I in SHA512.SHA512_Hash_Index => (Result (I) = Item (I)));
   is
      Result : SHA512.Block_Type := SHA512.Block_Type'(others => 0);
   begin
      for I in SHA512.SHA512_Hash_Index
      loop
         Result (I) := Item (I);
         --# assert
         --#    (I in SHA512.SHA512_Hash_Index) and
         --#    (I in SHA512.Block_Index) and
         --#    (for all Pos in SHA512.SHA512_Hash_Index range SHA512.SHA512_Hash_Index'First .. I =>
         --#         (Result (Pos) = Item (Pos)));
      end loop;
      return Result;
   end To_Block;

   ----------------------------------------------------------------------------

   function Context_Init (Key : SHA512.Block_Type) return Context_Type is
      Result : Context_Type;
      Temp   : SHA512.Block_Type;
   begin
      Debug.Put_Line ("HMAC.SHA512.Context_Init:");

      Result.Key            := Key;
      Result.SHA512_Context := SHA512.SHA512_Context_Init;
      Ops64.Block_XOR (IPad, Result.Key, Temp);
      SHA512.Context_Update (Result.SHA512_Context, Temp);
      return Result;
   end Context_Init;

   ----------------------------------------------------------------------------

   procedure Context_Update
     (Context : in out Context_Type;
      Block   : in SHA512.Block_Type)
   is
   begin
      Debug.Put_Line ("HMAC.SHA512.Context_Update:");
      SHA512.Context_Update (Context.SHA512_Context, Block);
   end Context_Update;

   ----------------------------------------------------------------------------

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     SHA512.Block_Type;
      Length  : in     SHA512.Block_Length_Type)
   is
      Hash : SHA512.SHA512_Hash_Type;
      Temp : SHA512.Block_Type;
   begin
      Debug.Put_Line ("HMAC.SHA512.Context_Finalize:");
      SHA512.Context_Finalize (Context.SHA512_Context, Block, Length);
      Hash := SHA512.SHA512_Get_Hash (Context.SHA512_Context);

      Context.SHA512_Context := SHA512.SHA512_Context_Init;
      Ops64.Block_XOR (OPad, Context.Key, Temp);
      SHA512.Context_Update (Context.SHA512_Context, Temp);
      SHA512.Context_Finalize (Context.SHA512_Context, To_Block (Hash), 512);
   end Context_Finalize;

   ----------------------------------------------------------------------------

   function Get_Prf (Context : in Context_Type) return SHA512.SHA512_Hash_Type is
   begin
      return SHA512.SHA512_Get_Hash (Context.SHA512_Context);
   end Get_Prf;

   ----------------------------------------------------------------------------

   function Get_Auth (Context : in Context_Type) return Auth_Type is
      Result : Auth_Type := Auth_Type'(others => 0);
      Prf    : SHA512.SHA512_Hash_Type;
   begin
      Prf := SHA512.SHA512_Get_Hash (Context.SHA512_Context);
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
      (Key     : SHA512.Block_Type;
       Message : SHA512.Message_Type;
       Length  : Types.Word64) return Auth_Type
   is
      HMAC_Ctx    : Context_Type;
      Dummy       : constant SHA512.Block_Type := SHA512.Block_Type'(others => 0);
      Last_Length : SHA512.Block_Length_Type;
      Last_Block  : SHA512.Message_Index;
   begin

      Debug.New_Line;
      Debug.Put_Line (">>> HMAC_SHA512.Authenticate start.");

      Last_Length := Length mod SHA512.Block_Size;
      Last_Block  := Message'First + Length / SHA512.Block_Size;

      HMAC_Ctx := Context_Init (Key);

      -- handle all blocks, but the last.
      if Last_Block > Message'First
      then
         for I in SHA512.Message_Index range Message'First .. Last_Block - 1
         loop
            --# assert
            --#    Last_Block = Last_Block% and
            --#    Last_Block <= Message'Last and
            --#    I < Last_Block;
            Context_Update (HMAC_Ctx, Message (I));

            Debug.Put ("    HMAC_SHA512.Authenticate: round ");
            Debug.Print_Word64 (I);
            Debug.Put_Line (".");
         end loop;
      end if;

      if Last_Length = 0
      then
         Debug.Put_Line ("    HMAC_SHA512.Authenticate: Empty last block");
         Context_Finalize (HMAC_Ctx, Dummy, 0);
      else
         Debug.Put ("    HMAC_SHA512.Authenticate: Partial last block of length ");
         Debug.Print_Word64 (Last_Length);
         Debug.Put_Line (".");
         Context_Finalize (HMAC_Ctx, Message (Last_Block), Last_Length);
      end if;

      Debug.Put_Line (">>> HMAC_SHA512.Authenticate end.");
      Debug.New_Line;

      return Get_Auth (HMAC_Ctx);
   end Authenticate;

end LSC.HMAC_SHA512;
