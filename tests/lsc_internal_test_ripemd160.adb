-------------------------------------------------------------------------------
--  This file is part of libsparkcrypto.
--
--  Copyright (C) 2018 Componolit GmbH
--  Copyright (C) 2010, Alexander Senier
--  Copyright (C) 2010, secunet Security Networks AG
--  All rights reserved.
--
--  Redistribution  and  use  in  source  and  binary  forms,  with  or  without
--  modification, are permitted provided that the following conditions are met:
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
--  THIS SOFTWARE IS PROVIDED BY THE  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
--  AND ANY  EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT LIMITED  TO, THE
--  IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
--  ARE  DISCLAIMED. IN  NO EVENT  SHALL  THE COPYRIGHT  HOLDER OR  CONTRIBUTORS
--  BE  LIABLE FOR  ANY  DIRECT, INDIRECT,  INCIDENTAL,  SPECIAL, EXEMPLARY,  OR
--  CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT  LIMITED  TO,  PROCUREMENT  OF
--  SUBSTITUTE GOODS  OR SERVICES; LOSS  OF USE,  DATA, OR PROFITS;  OR BUSINESS
--  INTERRUPTION)  HOWEVER CAUSED  AND ON  ANY THEORY  OF LIABILITY,  WHETHER IN
--  CONTRACT,  STRICT LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE OR  OTHERWISE)
--  ARISING IN ANY WAY  OUT OF THE USE OF THIS SOFTWARE, EVEN  IF ADVISED OF THE
--  POSSIBILITY OF SUCH DAMAGE.
-------------------------------------------------------------------------------

with LSC.Internal.Types;
with LSC.Internal.RIPEMD160;
with AUnit.Assertions; use AUnit.Assertions;
with Util; use Util;

use type LSC.Internal.Types.Word32_Array_Type;

pragma Style_Checks ("-s");
pragma Warnings (Off, "formal parameter ""T"" is not referenced");

package body LSC_Internal_Test_RIPEMD160 is

   --  RIPEMD-160: A Strengthened Version of RIPEMD , Appendix B: Test values
   --
   procedure Test_RIPEMD160_Empty (T : in out Test_Cases.Test_Case'Class)
   is
      Ctx             : LSC.Internal.RIPEMD160.Context_Type;
      Hash            : LSC.Internal.RIPEMD160.Hash_Type;
      Message         : LSC.Internal.RIPEMD160.Block_Type;
   begin

      --  "" (empty string)
      Ctx := LSC.Internal.RIPEMD160.Context_Init;
      Message := LSC.Internal.RIPEMD160.Block_Type'(others => 0);
      LSC.Internal.RIPEMD160.Context_Finalize (Ctx, Message, 0);
      Hash := LSC.Internal.RIPEMD160.Get_Hash (Ctx);

      Assert (Hash = LSC.Internal.RIPEMD160.Hash_Type'(M (16#9c1185a5#),
                                              M (16#c5e9fc54#),
                                              M (16#61280897#),
                                              M (16#7ee8f548#),
                                              M (16#b2258d31#)),
              "Hash differs");

   end Test_RIPEMD160_Empty;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_A (T : in out Test_Cases.Test_Case'Class)
   is
      Ctx             : LSC.Internal.RIPEMD160.Context_Type;
      Hash            : LSC.Internal.RIPEMD160.Hash_Type;
      Message         : LSC.Internal.RIPEMD160.Block_Type;
   begin

      --  "a"
      Ctx := LSC.Internal.RIPEMD160.Context_Init;
      Message := LSC.Internal.RIPEMD160.Block_Type'(M (16#61000000#), others => 0);
      LSC.Internal.RIPEMD160.Context_Finalize (Ctx, Message, 8);
      Hash := LSC.Internal.RIPEMD160.Get_Hash (Ctx);

      Assert (Hash = LSC.Internal.RIPEMD160.Hash_Type'(M (16#0bdc9d2d#),
                                              M (16#256b3ee9#),
                                              M (16#daae347b#),
                                              M (16#e6f4dc83#),
                                              M (16#5a467ffe#)),
              "Hash differs");

   end Test_RIPEMD160_A;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_ABC (T : in out Test_Cases.Test_Case'Class)
   is
      Ctx             : LSC.Internal.RIPEMD160.Context_Type;
      Hash            : LSC.Internal.RIPEMD160.Hash_Type;
      Message         : LSC.Internal.RIPEMD160.Block_Type;
   begin

      --  "abc"
      Ctx := LSC.Internal.RIPEMD160.Context_Init;
      Message := LSC.Internal.RIPEMD160.Block_Type'(M (16#61626300#), others => 0);
      LSC.Internal.RIPEMD160.Context_Finalize (Ctx, Message, 24);
      Hash := LSC.Internal.RIPEMD160.Get_Hash (Ctx);

      Assert (Hash = LSC.Internal.RIPEMD160.Hash_Type'(M (16#8eb208f7#),
                                              M (16#e05d987a#),
                                              M (16#9b044a8e#),
                                              M (16#98c6b087#),
                                              M (16#f15a0bfc#)),
              "Hash differs");

   end Test_RIPEMD160_ABC;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_Message_Digest (T : in out Test_Cases.Test_Case'Class)
   is
      Ctx             : LSC.Internal.RIPEMD160.Context_Type;
      Hash            : LSC.Internal.RIPEMD160.Hash_Type;
      Message         : LSC.Internal.RIPEMD160.Block_Type;
   begin

      --  "message digest"
      Ctx := LSC.Internal.RIPEMD160.Context_Init;
      Message := LSC.Internal.RIPEMD160.Block_Type'(M (16#6d657373#),
                                           M (16#61676520#),
                                           M (16#64696765#),
                                           M (16#73740000#),
                                           others => 0);
      LSC.Internal.RIPEMD160.Context_Finalize (Ctx, Message, 112);
      Hash := LSC.Internal.RIPEMD160.Get_Hash (Ctx);

      Assert (Hash = LSC.Internal.RIPEMD160.Hash_Type'(M (16#5d0689ef#),
                                              M (16#49d2fae5#),
                                              M (16#72b881b1#),
                                              M (16#23a85ffa#),
                                              M (16#21595f36#)),
              "Hash differs");

   end Test_RIPEMD160_Message_Digest;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_AtoZ (T : in out Test_Cases.Test_Case'Class)
   is
      Ctx             : LSC.Internal.RIPEMD160.Context_Type;
      Hash            : LSC.Internal.RIPEMD160.Hash_Type;
      Message         : LSC.Internal.RIPEMD160.Block_Type;
   begin

      --  "abcdefghijklmnopqrstuvwxyz"
      Ctx := LSC.Internal.RIPEMD160.Context_Init;
      Message := LSC.Internal.RIPEMD160.Block_Type'(M (16#61626364#),
                                           M (16#65666768#),
                                           M (16#696a6b6c#),
                                           M (16#6d6e6f70#),
                                           M (16#71727374#),
                                           M (16#75767778#),
                                           M (16#797a0000#),
                                           others => 0);

      LSC.Internal.RIPEMD160.Context_Finalize (Ctx, Message, 208);
      Hash := LSC.Internal.RIPEMD160.Get_Hash (Ctx);

      Assert (Hash = LSC.Internal.RIPEMD160.Hash_Type'(M (16#f71c2710#),
                                              M (16#9c692c1b#),
                                              M (16#56bbdceb#),
                                              M (16#5b9d2865#),
                                              M (16#b3708dbc#)),
              "Hash differs");

   end Test_RIPEMD160_AtoZ;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_ABCDEFG (T : in out Test_Cases.Test_Case'Class)
   is
      Ctx             : LSC.Internal.RIPEMD160.Context_Type;
      Hash            : LSC.Internal.RIPEMD160.Hash_Type;
      Message         : LSC.Internal.RIPEMD160.Block_Type;
   begin

      --  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
      Ctx := LSC.Internal.RIPEMD160.Context_Init;
      Message := LSC.Internal.RIPEMD160.Block_Type'(M (16#61626364#),
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
                                           others => 0);
      LSC.Internal.RIPEMD160.Context_Finalize (Ctx, Message, 448);
      Hash := LSC.Internal.RIPEMD160.Get_Hash (Ctx);

      Assert (Hash = LSC.Internal.RIPEMD160.Hash_Type'(M (16#12a05338#),
                                              M (16#4a9c0c88#),
                                              M (16#e405a06c#),
                                              M (16#27dcf49a#),
                                              M (16#da62eb2b#)),
              "Hash differs");

   end Test_RIPEMD160_ABCDEFG;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_AZaz09 (T : in out Test_Cases.Test_Case'Class)
   is
      Ctx             : LSC.Internal.RIPEMD160.Context_Type;
      Hash            : LSC.Internal.RIPEMD160.Hash_Type;
      Message         : LSC.Internal.RIPEMD160.Block_Type;
   begin

      --  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
      Ctx := LSC.Internal.RIPEMD160.Context_Init;
      Message := LSC.Internal.RIPEMD160.Block_Type'(M (16#41424344#),
                                           M (16#45464748#),
                                           M (16#494a4b4c#),
                                           M (16#4d4e4f50#),
                                           M (16#51525354#),
                                           M (16#55565758#),
                                           M (16#595a6162#),
                                           M (16#63646566#),
                                           M (16#6768696a#),
                                           M (16#6b6c6d6e#),
                                           M (16#6f707172#),
                                           M (16#73747576#),
                                           M (16#7778797a#),
                                           M (16#30313233#),
                                           M (16#34353637#),
                                           M (16#38390000#));
      LSC.Internal.RIPEMD160.Context_Finalize (Ctx, Message, 496);
      Hash := LSC.Internal.RIPEMD160.Get_Hash (Ctx);

      Assert (Hash = LSC.Internal.RIPEMD160.Hash_Type'(M (16#b0e20b6e#),
                                              M (16#31166402#),
                                              M (16#86ed3a87#),
                                              M (16#a5713079#),
                                              M (16#b21f5189#)),
              "Hash differs");

   end Test_RIPEMD160_AZaz09;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_8x1to0 (T : in out Test_Cases.Test_Case'Class)
   is
      Ctx             : LSC.Internal.RIPEMD160.Context_Type;
      Hash            : LSC.Internal.RIPEMD160.Hash_Type;
      Message         : LSC.Internal.RIPEMD160.Block_Type;
   begin

      --  8 times "1234567890"
      Ctx := LSC.Internal.RIPEMD160.Context_Init;
      Message := LSC.Internal.RIPEMD160.Block_Type'(M (16#31323334#),
                                           M (16#35363738#),
                                           M (16#39303132#),
                                           M (16#33343536#),
                                           M (16#37383930#),
                                           M (16#31323334#),
                                           M (16#35363738#),
                                           M (16#39303132#),
                                           M (16#33343536#),
                                           M (16#37383930#),
                                           M (16#31323334#),
                                           M (16#35363738#),
                                           M (16#39303132#),
                                           M (16#33343536#),
                                           M (16#37383930#),
                                           M (16#31323334#));
      LSC.Internal.RIPEMD160.Context_Update (Ctx, Message);

      Message := LSC.Internal.RIPEMD160.Block_Type'(M (16#35363738#),
                                           M (16#39303132#),
                                           M (16#33343536#),
                                           M (16#37383930#),
          others => 0);
      LSC.Internal.RIPEMD160.Context_Finalize (Ctx, Message, 128);
      Hash := LSC.Internal.RIPEMD160.Get_Hash (Ctx);

      Assert (Hash = LSC.Internal.RIPEMD160.Hash_Type'(M (16#9b752e45#),
                                              M (16#573d4b39#),
                                              M (16#f4dbd332#),
                                              M (16#3cab82bf#),
                                              M (16#63326bfb#)),
              "Hash differs");

   end Test_RIPEMD160_8x1to0;

   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160_1millionAs (T : in out Test_Cases.Test_Case'Class)
   is
      Ctx             : LSC.Internal.RIPEMD160.Context_Type;
      Hash            : LSC.Internal.RIPEMD160.Hash_Type;
      Message         : LSC.Internal.RIPEMD160.Block_Type;
   begin

      --  1 million times "a"
      Ctx := LSC.Internal.RIPEMD160.Context_Init;
      Message := LSC.Internal.RIPEMD160.Block_Type'(others => M (16#61616161#));

      for I in Natural range 1 .. 15625
      loop
         LSC.Internal.RIPEMD160.Context_Update (Ctx, Message);
      end loop;

      LSC.Internal.RIPEMD160.Context_Finalize (Ctx, Message, 0);
      Hash := LSC.Internal.RIPEMD160.Get_Hash (Ctx);

      Assert (Hash = LSC.Internal.RIPEMD160.Hash_Type'(M (16#52783243#),
                                              M (16#c1697bdb#),
                                              M (16#e16d37f9#),
                                              M (16#7f68f083#),
                                              M (16#25dc1528#)),
              "Hash differs");

   end Test_RIPEMD160_1millionAs;

   ---------------------------------------------------------------------------

   procedure Register_Tests (T : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Test_RIPEMD160_Empty'Access, "RIPEMD160 (empty string)");
      Register_Routine (T, Test_RIPEMD160_A'Access, "RIPEMD160 ('a')");
      Register_Routine (T, Test_RIPEMD160_ABC'Access, "RIPEMD160 ('abc')");
      Register_Routine (T, Test_RIPEMD160_Message_Digest'Access, "RIPEMD160 ('message digest')");
      Register_Routine (T, Test_RIPEMD160_AtoZ'Access, "RIPEMD160 ('a..z')");
      Register_Routine (T, Test_RIPEMD160_ABCDEFG'Access, "RIPEMD160 ('abcdefg...')");
      Register_Routine (T, Test_RIPEMD160_AZaz09'Access, "RIPEMD160 ('A..Za..z0..9')");
      Register_Routine (T, Test_RIPEMD160_8x1to0'Access, "RIPEMD160 (8x'1..0'");
      Register_Routine (T, Test_RIPEMD160_1millionAs'Access, "RIPEMD160 (1 million 'a's)");
   end Register_Tests;

   ---------------------------------------------------------------------------

   function Name (T : Test_Case) return Test_String is
   begin
      return Format ("RIPEMD160");
   end Name;

end LSC_Internal_Test_RIPEMD160;
