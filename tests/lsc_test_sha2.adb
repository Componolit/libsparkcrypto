-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2018 Componolit GmbH
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

with AUnit.Assertions; use AUnit.Assertions;
with Util; use Util;
with LSC.Internal.Types;
with LSC.Internal.SHA256;
with LSC.Internal.SHA512;

use type LSC.Internal.Types.Word32_Array_Type;
use type LSC.Internal.Types.Word64_Array_Type;

package body LSC_Test_SHA2 is

   procedure Test_SHA256_One_Block (T : in out Test_Cases.Test_Case'Class)
   is
      SHA256_Ctx : LSC.Internal.SHA256.Context_Type;
      Hash       : LSC.Internal.SHA256.SHA256_Hash_Type;
      Message    : LSC.Internal.SHA256.Block_Type;
   begin
      --  FIPS 180-2, Appendix C: SHA-256 Examples

      --  C.1 SHA-256 Example (One-Block Message)
      SHA256_Ctx := LSC.Internal.SHA256.SHA256_Context_Init;
      Message := LSC.Internal.SHA256.Block_Type'(M (16#61626300#), others => 16#fedca987#);
      LSC.Internal.SHA256.Context_Finalize (SHA256_Ctx, Message, 24);
      Hash := LSC.Internal.SHA256.SHA256_Get_Hash (SHA256_Ctx);

      Assert (Hash = LSC.Internal.SHA256.SHA256_Hash_Type'(M (16#ba7816bf#),
                                                  M (16#8f01cfea#),
                                                  M (16#414140de#),
                                                  M (16#5dae2223#),
                                                  M (16#b00361a3#),
                                                  M (16#96177a9c#),
                                                  M (16#b410ff61#),
                                                  M (16#f20015ad#)),
              "Hash differs");

   end Test_SHA256_One_Block;

   procedure Test_SHA256_Multi_Block (T : in out Test_Cases.Test_Case'Class)
   is
      SHA256_Ctx : LSC.Internal.SHA256.Context_Type;
      Hash       : LSC.Internal.SHA256.SHA256_Hash_Type;
      Message    : LSC.Internal.SHA256.Block_Type;
   begin

      --  C.2 SHA-256 Example (Multi-Block Message)
      SHA256_Ctx := LSC.Internal.SHA256.SHA256_Context_Init;
      Message :=
        LSC.Internal.SHA256.Block_Type'(M (16#61626364#),
                               M (16#62636465#),
                               M (16#63646566#),
                               M (16#64656667#),
                               M (16#65666768#),
                               M (16#66676869#),
                               M (16#6768696a#),
                               M (16#68696a6b#),
                               M (16#696a6b6c#),
                               M (16#6a6b6c6d#),
                               M (16#6b6c6d6e#),
                               M (16#6c6d6e6f#),
                               M (16#6d6e6f70#),
                               M (16#6e6f7071#),
                               M (16#0a000000#),
                               others => 16#deadbeef#);

      LSC.Internal.SHA256.Context_Finalize (SHA256_Ctx, Message, 448);
      Hash := LSC.Internal.SHA256.SHA256_Get_Hash (SHA256_Ctx);

      Assert (Hash = LSC.Internal.SHA256.SHA256_Hash_Type'(M (16#248d6a61#),
                                                  M (16#d20638b8#),
                                                  M (16#e5c02693#),
                                                  M (16#0c3e6039#),
                                                  M (16#a33ce459#),
                                                  M (16#64ff2167#),
                                                  M (16#f6ecedd4#),
                                                  M (16#19db06c1#)),
              "Hash differs");

   end Test_SHA256_Multi_Block;

   procedure Test_SHA256_Long (T : in out Test_Cases.Test_Case'Class)
   is
      SHA256_Ctx : LSC.Internal.SHA256.Context_Type;
      Hash       : LSC.Internal.SHA256.SHA256_Hash_Type;
      Message    : LSC.Internal.SHA256.Block_Type;
   begin

      --  C.3 SHA-256 Example (Long Message)
      Message := LSC.Internal.SHA256.Block_Type'(others => M (16#61616161#));

      SHA256_Ctx := LSC.Internal.SHA256.SHA256_Context_Init;
      for I in Natural range 1 .. 15625
      loop
         LSC.Internal.SHA256.Context_Update (SHA256_Ctx, Message);
      end loop;
      LSC.Internal.SHA256.Context_Finalize (SHA256_Ctx, Message, 0);
      Hash := LSC.Internal.SHA256.SHA256_Get_Hash (SHA256_Ctx);

      Assert (Hash = LSC.Internal.SHA256.SHA256_Hash_Type'(M (16#cdc76e5c#),
                                                  M (16#9914fb92#),
                                                  M (16#81a1c7e2#),
                                                  M (16#84d73e67#),
                                                  M (16#f1809a48#),
                                                  M (16#a497200e#),
                                                  M (16#046d39cc#),
                                                  M (16#c7112cd0#)),
              "Hash differ");

   end Test_SHA256_Long;

   ---------------------------------------------------------------------------

   procedure Test_SHA384_One_Block (T : in out Test_Cases.Test_Case'Class)
   is
      SHA512_Ctx : LSC.Internal.SHA512.Context_Type;
      Hash       : LSC.Internal.SHA512.SHA384_Hash_Type;
      Message    : LSC.Internal.SHA512.Block_Type;
   begin
      --  FIPS 180-2, Appendix C: SHA-384 Examples
      --  D.1 SHA-384 Example (One-Block Message)
      SHA512_Ctx := LSC.Internal.SHA512.SHA384_Context_Init;
      Message := LSC.Internal.SHA512.Block_Type'(N (16#6162630000000000#),
                                        others => 16#deadbeefcafebabe#);
      LSC.Internal.SHA512.Context_Finalize (SHA512_Ctx, Message, 24);
      Hash := LSC.Internal.SHA512.SHA384_Get_Hash (SHA512_Ctx);

      Assert (Hash = LSC.Internal.SHA512.SHA384_Hash_Type'(N (16#cb00753f45a35e8b#),
                                                  N (16#b5a03d699ac65007#),
                                                  N (16#272c32ab0eded163#),
                                                  N (16#1a8b605a43ff5bed#),
                                                  N (16#8086072ba1e7cc23#),
                                                  N (16#58baeca134c825a7#)),
              "Hash differs");

   end Test_SHA384_One_Block;

   ---------------------------------------------------------------------------

   procedure Test_SHA384_Multi_Block (T : in out Test_Cases.Test_Case'Class)
   is
      SHA512_Ctx : LSC.Internal.SHA512.Context_Type;
      Hash       : LSC.Internal.SHA512.SHA384_Hash_Type;
      Message    : LSC.Internal.SHA512.Block_Type;
   begin

      --  D.2 SHA-384 Example (Multi-Block Message)
      SHA512_Ctx := LSC.Internal.SHA512.SHA384_Context_Init;
      Message :=
        LSC.Internal.SHA512.Block_Type'
        (N (16#6162636465666768#),
         N (16#6263646566676869#),
         N (16#636465666768696a#),
         N (16#6465666768696a6b#),
         N (16#65666768696a6b6c#),
         N (16#666768696a6b6c6d#),
         N (16#6768696a6b6c6d6e#),
         N (16#68696a6b6c6d6e6f#),
         N (16#696a6b6c6d6e6f70#),
         N (16#6a6b6c6d6e6f7071#),
         N (16#6b6c6d6e6f707172#),
         N (16#6c6d6e6f70717273#),
         N (16#6d6e6f7071727374#),
         N (16#6e6f707172737475#),
         N (16#0000000000000000#),
         N (16#0000000000000000#));
      LSC.Internal.SHA512.Context_Finalize (SHA512_Ctx, Message, 896);
      Hash := LSC.Internal.SHA512.SHA384_Get_Hash (SHA512_Ctx);

      Assert (Hash = LSC.Internal.SHA512.SHA384_Hash_Type'(N (16#09330c33f71147e8#),
                                                  N (16#3d192fc782cd1b47#),
                                                  N (16#53111b173b3b05d2#),
                                                  N (16#2fa08086e3b0f712#),
                                                  N (16#fcc7c71a557e2db9#),
                                                  N (16#66c3e9fa91746039#)),
              "Hash differs");

   end Test_SHA384_Multi_Block;

   ---------------------------------------------------------------------------

   procedure Test_SHA384_Long (T : in out Test_Cases.Test_Case'Class)
   is
      SHA512_Ctx : LSC.Internal.SHA512.Context_Type;
      Hash       : LSC.Internal.SHA512.SHA384_Hash_Type;
      Message    : LSC.Internal.SHA512.Block_Type;
   begin

      --  D.3 SHA-384 Example (Long Message)
      Message := LSC.Internal.SHA512.Block_Type'(others => N (16#6161616161616161#));

      SHA512_Ctx := LSC.Internal.SHA512.SHA384_Context_Init;
      for I in Natural range 1 .. 7812
      loop
         LSC.Internal.SHA512.Context_Update (SHA512_Ctx, Message);
      end loop;
      LSC.Internal.SHA512.Context_Finalize (SHA512_Ctx, Message, 512);
      Hash := LSC.Internal.SHA512.SHA384_Get_Hash (SHA512_Ctx);

      Assert (Hash = LSC.Internal.SHA512.SHA384_Hash_Type'(N (16#9d0e1809716474cb#),
                                                  N (16#086e834e310a4a1c#),
                                                  N (16#ed149e9c00f24852#),
                                                  N (16#7972cec5704c2a5b#),
                                                  N (16#07b8b3dc38ecc4eb#),
                                                  N (16#ae97ddd87f3d8985#)),
              "Hash differs");

   end Test_SHA384_Long;

   ---------------------------------------------------------------------------

   procedure Test_SHA512_One_Block (T : in out Test_Cases.Test_Case'Class)
   is
      SHA512_Ctx : LSC.Internal.SHA512.Context_Type;
      Hash       : LSC.Internal.SHA512.SHA512_Hash_Type;
      Message    : LSC.Internal.SHA512.Block_Type;
   begin
      --  FIPS 180-2, Appendix C: SHA-512 Examples
      --  C.1 SHA-512 Example (One-Block Message)
      SHA512_Ctx := LSC.Internal.SHA512.SHA512_Context_Init;
      Message := LSC.Internal.SHA512.Block_Type'(N (16#616263f4aabc124d#),
                                         others => 16#deadc0dedeadbeef#);
      LSC.Internal.SHA512.Context_Finalize (SHA512_Ctx, Message, 24);
      Hash := LSC.Internal.SHA512.SHA512_Get_Hash (SHA512_Ctx);

      Assert (Hash = LSC.Internal.SHA512.SHA512_Hash_Type'(N (16#ddaf35a193617aba#),
                                                  N (16#cc417349ae204131#),
                                                  N (16#12e6fa4e89a97ea2#),
                                                  N (16#0a9eeee64b55d39a#),
                                                  N (16#2192992a274fc1a8#),
                                                  N (16#36ba3c23a3feebbd#),
                                                  N (16#454d4423643ce80e#),
                                                  N (16#2a9ac94fa54ca49f#)),
              "Hash differs");

   end Test_SHA512_One_Block;

   ---------------------------------------------------------------------------

   procedure Test_SHA512_Multi_Block (T : in out Test_Cases.Test_Case'Class)
   is
      SHA512_Ctx : LSC.Internal.SHA512.Context_Type;
      Hash       : LSC.Internal.SHA512.SHA512_Hash_Type;
      Message    : LSC.Internal.SHA512.Block_Type;
   begin

      --  C.2 SHA-512 Example (Multi-Block Message)
      SHA512_Ctx := LSC.Internal.SHA512.SHA512_Context_Init;
      Message :=
        LSC.Internal.SHA512.Block_Type'
        (N (16#6162636465666768#),
         N (16#6263646566676869#),
         N (16#636465666768696a#),
         N (16#6465666768696a6b#),
         N (16#65666768696a6b6c#),
         N (16#666768696a6b6c6d#),
         N (16#6768696a6b6c6d6e#),
         N (16#68696a6b6c6d6e6f#),
         N (16#696a6b6c6d6e6f70#),
         N (16#6a6b6c6d6e6f7071#),
         N (16#6b6c6d6e6f707172#),
         N (16#6c6d6e6f70717273#),
         N (16#6d6e6f7071727374#),
         N (16#6e6f707172737475#),
         N (16#f423ae49fac82234#),
         N (16#deadbeefcafe0000#));
      LSC.Internal.SHA512.Context_Finalize (SHA512_Ctx, Message, 896);
      Hash := LSC.Internal.SHA512.SHA512_Get_Hash (SHA512_Ctx);

      Assert (Hash = LSC.Internal.SHA512.SHA512_Hash_Type'(N (16#8e959b75dae313da#),
                                                  N (16#8cf4f72814fc143f#),
                                                  N (16#8f7779c6eb9f7fa1#),
                                                  N (16#7299aeadb6889018#),
                                                  N (16#501d289e4900f7e4#),
                                                  N (16#331b99dec4b5433a#),
                                                  N (16#c7d329eeb6dd2654#),
                                                  N (16#5e96e55b874be909#)),
              "Hash differs");

   end Test_SHA512_Multi_Block;

   ---------------------------------------------------------------------------

   procedure Test_SHA512_Long (T : in out Test_Cases.Test_Case'Class)
   is
      SHA512_Ctx : LSC.Internal.SHA512.Context_Type;
      Hash       : LSC.Internal.SHA512.SHA512_Hash_Type;
      Message    : LSC.Internal.SHA512.Block_Type;
   begin

      --  C.3 SHA-512 Example (Long Message)
      Message := LSC.Internal.SHA512.Block_Type'(others => N (16#6161616161616161#));

      SHA512_Ctx := LSC.Internal.SHA512.SHA512_Context_Init;
      for I in Natural range 1 .. 7812
      loop
         LSC.Internal.SHA512.Context_Update (SHA512_Ctx, Message);
      end loop;
      LSC.Internal.SHA512.Context_Finalize (SHA512_Ctx, Message, 512);
      Hash := LSC.Internal.SHA512.SHA512_Get_Hash (SHA512_Ctx);

      Assert (Hash = LSC.Internal.SHA512.SHA512_Hash_Type'(N (16#e718483d0ce76964#),
                                                  N (16#4e2e42c7bc15b463#),
                                                  N (16#8e1f98b13b204428#),
                                                  N (16#5632a803afa973eb#),
                                                  N (16#de0ff244877ea60a#),
                                                  N (16#4cb0432ce577c31b#),
                                                  N (16#eb009c5c2c49aa2e#),
                                                  N (16#4eadb217ad8cc09b#)),
              "Hash differs");

   end Test_SHA512_Long;

   ---------------------------------------------------------------------------

   procedure Register_Tests (T: in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Test_SHA256_One_Block'Access, "SHA-256 (One-Block Message)");
      Register_Routine (T, Test_SHA256_Multi_Block'Access, "SHA-256 (Multi-Block Message)");
      Register_Routine (T, Test_SHA256_Long'Access, "SHA-256 (Long Message)");
      Register_Routine (T, Test_SHA384_One_Block'Access, "SHA-384 (One-Block Message)");
      Register_Routine (T, Test_SHA384_Multi_Block'Access, "SHA-384 (Multi-Block Message)");
      Register_Routine (T, Test_SHA384_Long'Access, "SHA-384 (Long Message)");
      Register_Routine (T, Test_SHA512_One_Block'Access, "SHA-512 (One-Block Message)");
      Register_Routine (T, Test_SHA512_Multi_Block'Access, "SHA-512 (Multi-Block Message)");
      Register_Routine (T, Test_SHA512_Long'Access, "SHA-512 (Long Message)");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("SHA2");
   end Name;

end LSC_Test_SHA2;
