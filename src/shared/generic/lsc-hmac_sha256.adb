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

with LSC.Debug;
with LSC.Ops32;

package body LSC.HMAC_SHA256 is

   IPad : constant SHA256.Block_Type :=
      SHA256.Block_Type'(SHA256.Block_Index => 16#36363636#);
   OPad : constant SHA256.Block_Type :=
      SHA256.Block_Type'(SHA256.Block_Index => 16#5C5C5C5C#);

   ----------------------------------------------------------------------------

   function Context_Init (Key : SHA256.Block_Type) return Context_Type is
      Result : Context_Type;
      Temp   : SHA256.Block_Type;
   begin
      pragma Debug (Debug.Put_Line ("HMAC.SHA256.Context_Init:"));

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
      pragma Debug (Debug.Put_Line ("HMAC.SHA256.Context_Update:"));
      SHA256.Context_Update (Context.SHA256_Context, Block);
   end Context_Update;

   ----------------------------------------------------------------------------

   procedure Context_Finalize_Outer
     (Context : in out Context_Type)
     with Depends => (Context => Context)
   is
      Hash : SHA256.SHA256_Hash_Type;
      Temp : SHA256.Block_Type;
   begin
      Hash := SHA256.SHA256_Get_Hash (Context.SHA256_Context);

      Context.SHA256_Context := SHA256.SHA256_Context_Init;
      Ops32.Block_XOR (OPad, Context.Key, Temp);
      SHA256.Context_Update (Context.SHA256_Context, Temp);
      Temp := SHA256.Null_Block;
      Ops32.Block_Copy (Hash, Temp);
      SHA256.Context_Finalize (Context.SHA256_Context, Temp, 256);
   end Context_Finalize_Outer;

   ----------------------------------------------------------------------------

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     SHA256.Block_Type;
      Length  : in     SHA256.Block_Length_Type)
   is
   begin
      pragma Debug (Debug.Put_Line ("HMAC.SHA256.Context_Finalize:"));
      SHA256.Context_Finalize (Context.SHA256_Context, Block, Length);
      Context_Finalize_Outer (Context);
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
      loop
         pragma Loop_Invariant
           (for all I in SHA256.SHA256_Hash_Index => (Prf (I) in Types.Word32));
         Result (Index) := Prf (Index);
      end loop;

      return Result;
   end Get_Auth;

   ----------------------------------------------------------------------------

   function Keyed_Hash
      (Key     : SHA256.Block_Type;
       Message : SHA256.Message_Type;
       Length  : Types.Word64) return Context_Type
     with Pre => Length <= Message'Length * SHA256.Block_Size
   is
      HMAC_Ctx : Context_Type;
   begin
      HMAC_Ctx := Context_Init (Key);
      SHA256.Hash_Context (Message, Length, HMAC_Ctx.SHA256_Context);
      Context_Finalize_Outer (HMAC_Ctx);

      return HMAC_Ctx;
   end Keyed_Hash;

   ----------------------------------------------------------------------------

   function Pseudorandom
      (Key     : SHA256.Block_Type;
       Message : SHA256.Message_Type;
       Length  : Types.Word64) return SHA256.SHA256_Hash_Type
   is
   begin
      return Get_Prf (Keyed_Hash (Key, Message, Length));
   end Pseudorandom;

   ----------------------------------------------------------------------------

   function Authenticate
      (Key     : SHA256.Block_Type;
       Message : SHA256.Message_Type;
       Length  : Types.Word64) return Auth_Type
   is
   begin
      return Get_Auth (Keyed_Hash (Key, Message, Length));
   end Authenticate;

end LSC.HMAC_SHA256;
