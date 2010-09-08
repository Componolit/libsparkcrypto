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

with LSC.Ops32;
with LSC.Debug;

package body LSC.HMAC_RIPEMD160 is

   IPad : constant RIPEMD160.Block_Type :=
      RIPEMD160.Block_Type'(RIPEMD160.Block_Index => 16#36363636#);
   OPad : constant RIPEMD160.Block_Type :=
      RIPEMD160.Block_Type'(RIPEMD160.Block_Index => 16#5C5C5C5C#);

   ----------------------------------------------------------------------------

   function Context_Init (Key : RIPEMD160.Block_Type) return Context_Type is
      Result : Context_Type;
      Temp   : RIPEMD160.Block_Type;
   begin
      pragma Debug (Debug.Put_Line ("HMAC.RIPEMD160.Context_Init:"));

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
      pragma Debug (Debug.Put_Line ("HMAC.RIPEMD160.Context_Update:"));
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
      pragma Debug (Debug.Put_Line ("HMAC.RIPEMD160.Context_Finalize:"));
      RIPEMD160.Context_Finalize (Context.RIPEMD160_Context, Block, Length);
      Hash := RIPEMD160.Get_Hash (Context.RIPEMD160_Context);

      Context.RIPEMD160_Context := RIPEMD160.Context_Init;
      Ops32.Block_XOR (OPad, Context.Key, Temp);
      RIPEMD160.Context_Update (Context.RIPEMD160_Context, Temp);
      Temp := RIPEMD160.Null_Block;
      Ops32.Block_Copy (Hash, Temp);
      RIPEMD160.Context_Finalize (Context.RIPEMD160_Context, Temp, 160);
   end Context_Finalize;

   ----------------------------------------------------------------------------

   function Get_Auth (Context : in Context_Type) return RIPEMD160.Hash_Type is
   begin
      return RIPEMD160.Get_Hash (Context.RIPEMD160_Context);
   end Get_Auth;

   ----------------------------------------------------------------------------

   function Authenticate
      (Key     : RIPEMD160.Block_Type;
       Message : RIPEMD160.Message_Type;
       Length  : Types.Word64) return RIPEMD160.Hash_Type
   is
      HMAC_Ctx    : Context_Type;
      Dummy       : constant RIPEMD160.Block_Type := RIPEMD160.Null_Block;
      Last_Length : RIPEMD160.Block_Length_Type;
      Last_Block  : RIPEMD160.Message_Index;
   begin

      pragma Debug (Debug.New_Line);
      pragma Debug (Debug.Put_Line (">>> HMAC_RIPEMD160.Authenticate start."));

      Last_Length := Types.Word32 (Length mod RIPEMD160.Block_Size);
      Last_Block  := Message'First + Length / RIPEMD160.Block_Size;

      HMAC_Ctx := Context_Init (Key);

      -- handle all blocks, but the last.
      if Last_Block > Message'First then
         for I in RIPEMD160.Message_Index range Message'First .. Last_Block - 1
         loop
            --# assert
            --#    Last_Block = Last_Block% and
            --#    Last_Block <= Message'Last and
            --#    I < Last_Block;
            Context_Update (HMAC_Ctx, Message (I));

            pragma Debug (Debug.Put ("    HMAC_RIPEMD160.Authenticate: round "));
            pragma Debug (Debug.Print_Word64 (I));
            pragma Debug (Debug.Put_Line ("."));
         end loop;
      end if;

      if Last_Length = 0 then
         pragma Debug (Debug.Put_Line ("    HMAC_RIPEMD160.Authenticate: Empty last block"));
         Context_Finalize (HMAC_Ctx, Dummy, 0);
      else
         pragma Debug (Debug.Put ("    HMAC_RIPEMD160.Authenticate: Partial last block of length "));
         pragma Debug (Debug.Print_Word32 (Last_Length));
         pragma Debug (Debug.Put_Line ("."));
         Context_Finalize (HMAC_Ctx, Message (Last_Block), Last_Length);
      end if;

      pragma Debug (Debug.Put_Line (">>> HMAC_RIPEMD160.Authenticate end."));
      pragma Debug (Debug.New_Line);

      return Get_Auth (HMAC_Ctx);
   end Authenticate;

end LSC.HMAC_RIPEMD160;
