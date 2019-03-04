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

with LSC.Internal.Ops64;
with LSC.Internal.Debug;
pragma Unreferenced (LSC.Internal.Debug);

package body LSC.Internal.HMAC_SHA384 is

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

   procedure Context_Finalize_Outer
     (Context : in out Context_Type)
     with Depends => (Context => Context)
   is
      Hash : SHA512.SHA384_Hash_Type;
      Temp : SHA512.Block_Type;
   begin
      Hash := SHA512.SHA384_Get_Hash (Context.SHA384_Context);

      Context.SHA384_Context := SHA512.SHA384_Context_Init;
      Ops64.Block_XOR (OPad, Context.Key, Temp);
      SHA512.Context_Update (Context.SHA384_Context, Temp);
      Temp := SHA512.Null_Block;
      Ops64.Block_Copy (Hash, Temp);
      SHA512.Context_Finalize (Context.SHA384_Context, Temp, 384);
   end Context_Finalize_Outer;

   ----------------------------------------------------------------------------

   procedure Context_Finalize
     (Context : in out Context_Type;
      Block   : in     SHA512.Block_Type;
      Length  : in     SHA512.Block_Length_Type)
   is
   begin
      pragma Debug (Debug.Put_Line ("HMAC.SHA384.Context_Finalize:"));
      SHA512.Context_Finalize (Context.SHA384_Context, Block, Length);
      Context_Finalize_Outer (Context);
   end Context_Finalize;

   ----------------------------------------------------------------------------

   function Get_Prf (Context : in Context_Type) return SHA512.SHA384_Hash_Type is
   begin
      return SHA512.SHA384_Get_Hash (Context.SHA384_Context);
   end Get_Prf;

   ----------------------------------------------------------------------------

   function Get_Auth (Context : in Context_Type) return Auth_Type is
      Result : Auth_Type;
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

   function Keyed_Hash
      (Key     : SHA512.Block_Type;
       Message : SHA512.Message_Type;
       Length  : SHA512.Message_Index) return Context_Type
     with
       Pre =>
         Message'First <= Message'Last and
         Length / SHA512.Block_Size +
         (if Length mod SHA512.Block_Size = 0 then 0 else 1) <= Message'Length
   is
      HMAC_Ctx : Context_Type;
   begin
      HMAC_Ctx := Context_Init (Key);
      SHA512.Hash_Context (Message, Length, HMAC_Ctx.SHA384_Context);
      Context_Finalize_Outer (HMAC_Ctx);

      return HMAC_Ctx;
   end Keyed_Hash;

   ----------------------------------------------------------------------------

   function Pseudorandom
      (Key     : SHA512.Block_Type;
       Message : SHA512.Message_Type;
       Length  : SHA512.Message_Index) return SHA512.SHA384_Hash_Type
   is
   begin
      return Get_Prf (Keyed_Hash (Key, Message, Length));
   end Pseudorandom;

   ----------------------------------------------------------------------------

   function Authenticate
      (Key     : SHA512.Block_Type;
       Message : SHA512.Message_Type;
       Length  : SHA512.Message_Index) return Auth_Type
   is
   begin
      return Get_Auth (Keyed_Hash (Key, Message, Length));
   end Authenticate;

end LSC.Internal.HMAC_SHA384;
