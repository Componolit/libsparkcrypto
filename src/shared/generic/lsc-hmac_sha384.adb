-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2010, Alexander Senier
-- Copyright (C) 2010, secunet Security Networks AG
-- All rights reserved.
--
-- Redistribution  and  use  in  source  and  binary  forms,  with  or  without
-- modification, are permitted provided that the following conditions are met:
--
--    * Redistributions of source code must retain the above copyright notice,
--      this list of conditions and the following disclaimer.
--
--    * Redistributions in binary form must reproduce the above copyright
--      notice, this list of conditions and the following disclaimer in the
--      documentation and/or other materials provided with the distribution.
--
--    * Neither the name of the  nor the names of its contributors may be used
--      to endorse or promote products derived from this software without
--      specific prior written permission.
--
-- THIS SOFTWARE IS PROVIDED BY THE  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-- AND ANY  EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT LIMITED  TO, THE
-- IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
-- ARE  DISCLAIMED. IN  NO EVENT  SHALL  THE COPYRIGHT  HOLDER OR  CONTRIBUTORS
-- BE  LIABLE FOR  ANY  DIRECT, INDIRECT,  INCIDENTAL,  SPECIAL, EXEMPLARY,  OR
-- CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT  LIMITED  TO,  PROCUREMENT  OF
-- SUBSTITUTE GOODS  OR SERVICES; LOSS  OF USE,  DATA, OR PROFITS;  OR BUSINESS
-- INTERRUPTION)  HOWEVER CAUSED  AND ON  ANY THEORY  OF LIABILITY,  WHETHER IN
-- CONTRACT,  STRICT LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE OR  OTHERWISE)
-- ARISING IN ANY WAY  OUT OF THE USE OF THIS SOFTWARE, EVEN  IF ADVISED OF THE
-- POSSIBILITY OF SUCH DAMAGE.
-------------------------------------------------------------------------------

with LSC.Ops64;
with LSC.Debug;

package body LSC.HMAC_SHA384 is

   IPad : constant SHA512.Block_Type :=
      SHA512.Block_Type'(SHA512.Block_Index => 16#36363636_36363636#);
   OPad : constant SHA512.Block_Type :=
      SHA512.Block_Type'(SHA512.Block_Index => 16#5C5C5C5C_5C5C5C5C#);

   ----------------------------------------------------------------------------

   function Context_Init (Key : SHA512.Block_Type) return Context_Type is
      Result : Context_Type;
      Temp   : SHA512.Block_Type;
   begin
      pragma Debug (Debug.Put_Line ("HMAC.SHA384.Context_Init:"));

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
      pragma Debug (Debug.Put_Line ("HMAC.SHA384.Context_Update:"));
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
      pragma Debug (Debug.Put_Line ("HMAC.SHA384.Context_Finalize:"));
      SHA512.Context_Finalize (Context.SHA384_Context, Block, Length);
      Hash := SHA512.SHA384_Get_Hash (Context.SHA384_Context);

      Context.SHA384_Context := SHA512.SHA384_Context_Init;
      Ops64.Block_XOR (OPad, Context.Key, Temp);
      SHA512.Context_Update (Context.SHA384_Context, Temp);
      Temp := SHA512.Null_Block;
      Ops64.Block_Copy (Hash, Temp);
      SHA512.Context_Finalize (Context.SHA384_Context, Temp, 384);
   end Context_Finalize;

   ----------------------------------------------------------------------------

   function Get_Prf (Context : in Context_Type) return SHA512.SHA384_Hash_Type is
   begin
      return SHA512.SHA384_Get_Hash (Context.SHA384_Context);
   end Get_Prf;

   ----------------------------------------------------------------------------

   function Get_Auth (Context : in Context_Type) return Auth_Type is
      Result : Auth_Type := Null_Auth;
      Prf    : SHA512.SHA384_Hash_Type;
   begin
      Prf := SHA512.SHA384_Get_Hash (Context.SHA384_Context);
      for Index in Auth_Index
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
      Dummy       : constant SHA512.Block_Type := SHA512.Null_Block;
      Last_Length : SHA512.Block_Length_Type;
      Last_Block  : SHA512.Message_Index;
   begin

      pragma Debug (Debug.New_Line);
      pragma Debug (Debug.Put_Line (">>> HMAC_SHA384.Authenticate start."));

      Last_Length := Length mod SHA512.Block_Size;
      Last_Block  := Message'First + Length / SHA512.Block_Size;

      HMAC_Ctx := Context_Init (Key);

      -- handle all blocks, but the last.
      if Last_Block > Message'First then
         for I in SHA512.Message_Index range Message'First .. Last_Block - 1
         loop
            --# assert
            --#    Last_Block = Last_Block% and
            --#    Last_Block <= Message'Last and
            --#    I < Last_Block;
            Context_Update (HMAC_Ctx, Message (I));

            pragma Debug (Debug.Put ("    HMAC_SHA384.Authenticate: round "));
            pragma Debug (Debug.Print_Word64 (I));
            pragma Debug (Debug.Put_Line ("."));
         end loop;
      end if;

      if Last_Length = 0 then
         pragma Debug (Debug.Put_Line ("    HMAC_SHA384.Authenticate: Empty last block"));
         Context_Finalize (HMAC_Ctx, Dummy, 0);
      else
         pragma Debug (Debug.Put ("    HMAC_SHA384.Authenticate: Partial last block of length "));
         pragma Debug (Debug.Print_Word64 (Last_Length));
         pragma Debug (Debug.Put_Line ("."));
         Context_Finalize (HMAC_Ctx, Message (Last_Block), Last_Length);
      end if;

      pragma Debug (Debug.Put_Line (">>> HMAC_SHA384.Authenticate end."));
      pragma Debug (Debug.New_Line);

      return Get_Auth (HMAC_Ctx);
   end Authenticate;

end LSC.HMAC_SHA384;
