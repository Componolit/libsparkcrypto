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

separate (Main)
procedure SHA384_Tests is
   SHA384_Suite                           : SPARKUnit.Index_Type;
   SHA512_Ctx1, SHA512_Ctx2, SHA512_Ctx3  : LSC.SHA512.Context_Type;
   Hash1, Hash2, Hash3                    : LSC.SHA512.SHA384_Hash_Type;
   Message1, Message2, Message3           : LSC.SHA512.Block_Type;
begin

   SPARKUnit.Create_Suite (Harness, "SHA-384 tests", SHA384_Suite);

   --  FIPS 180-2, Appendix C: SHA-384 Examples

   --  D.1 SHA-384 Example (One-Block Message)
   SHA512_Ctx1 := LSC.SHA512.SHA384_Context_Init;
   Message1 := LSC.SHA512.Block_Type'(N (16#6162630000000000#),
                                      others => 16#deadbeefcafebabe#);
   LSC.SHA512.Context_Finalize (SHA512_Ctx1, Message1, 24);
   Hash1 := LSC.SHA512.SHA384_Get_Hash (SHA512_Ctx1);

   SPARKUnit.Create_Test
     (Harness,
      SHA384_Suite,
      "SHA-384 Example (One-Block Message)",
      Hash1 =
      LSC.SHA512.SHA384_Hash_Type'(N (16#cb00753f45a35e8b#),
                                   N (16#b5a03d699ac65007#),
                                   N (16#272c32ab0eded163#),
                                   N (16#1a8b605a43ff5bed#),
                                   N (16#8086072ba1e7cc23#),
                                   N (16#58baeca134c825a7#)));

   --  D.2 SHA-384 Example (Multi-Block Message)
   SHA512_Ctx2     := LSC.SHA512.SHA384_Context_Init;
   Message2 :=
     LSC.SHA512.Block_Type'
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
   LSC.SHA512.Context_Finalize (SHA512_Ctx2, Message2, 896);
   Hash2 := LSC.SHA512.SHA384_Get_Hash (SHA512_Ctx2);

   SPARKUnit.Create_Test
     (Harness,
      SHA384_Suite,
      "SHA-384 Example (Multi-Block Message)",
      Hash2 =
      LSC.SHA512.SHA384_Hash_Type'(N (16#09330c33f71147e8#),
                                   N (16#3d192fc782cd1b47#),
                                   N (16#53111b173b3b05d2#),
                                   N (16#2fa08086e3b0f712#),
                                   N (16#fcc7c71a557e2db9#),
                                   N (16#66c3e9fa91746039#)));

   --  D.3 SHA-384 Example (Long Message)
   Message3 := LSC.SHA512.Block_Type'(others => N (16#6161616161616161#));

   SHA512_Ctx3 := LSC.SHA512.SHA384_Context_Init;
   for I in Natural range 1 .. 7812
      --#  assert I in Natural;
   loop
      LSC.SHA512.Context_Update (SHA512_Ctx3, Message3);
   end loop;
   LSC.SHA512.Context_Finalize (SHA512_Ctx3, Message3, 512);
   Hash3 := LSC.SHA512.SHA384_Get_Hash (SHA512_Ctx3);

   SPARKUnit.Create_Test
     (Harness,
      SHA384_Suite,
      "SHA-384 Example (Long Message)",
      Hash3 =
      LSC.SHA512.SHA384_Hash_Type'(N (16#9d0e1809716474cb#),
                                   N (16#086e834e310a4a1c#),
                                   N (16#ed149e9c00f24852#),
                                   N (16#7972cec5704c2a5b#),
                                   N (16#07b8b3dc38ecc4eb#),
                                   N (16#ae97ddd87f3d8985#)));

end SHA384_Tests;
