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

with LSC.Internal.Ops32;
with LSC.Internal.Debug;

package body LSC.Internal.HMAC_RIPEMD160 is

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

   procedure Context_Finalize_Outer
     (Context : in out Context_Type)
     with Depends => (Context => Context)
   is
      Hash : RIPEMD160.Hash_Type;
      Temp : RIPEMD160.Block_Type;
   begin
      Hash := RIPEMD160.Get_Hash (Context.RIPEMD160_Context);

      Context.RIPEMD160_Context := RIPEMD160.Context_Init;
      Ops32.Block_XOR (OPad, Context.Key, Temp);
      RIPEMD160.Context_Update (Context.RIPEMD160_Context, Temp);
      Temp := RIPEMD160.Null_Block;
      Ops32.Block_Copy (Hash, Temp);
      RIPEMD160.Context_Finalize (Context.RIPEMD160_Context, Temp, 160);
   end Context_Finalize_Outer;

   ----------------------------------------------------------------------------

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     RIPEMD160.Block_Type;
      Length  : in     RIPEMD160.Block_Length_Type)
   is
   begin
      pragma Debug (Debug.Put_Line ("HMAC.RIPEMD160.Context_Finalize:"));
      RIPEMD160.Context_Finalize (Context.RIPEMD160_Context, Block, Length);
      Context_Finalize_Outer (Context);
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
      HMAC_Ctx : Context_Type;
   begin
      HMAC_Ctx := Context_Init (Key);
      RIPEMD160.Hash_Context (Message, Length, HMAC_Ctx.RIPEMD160_Context);
      Context_Finalize_Outer (HMAC_Ctx);

      return Get_Auth (HMAC_Ctx);
   end Authenticate;

end LSC.Internal.HMAC_RIPEMD160;
