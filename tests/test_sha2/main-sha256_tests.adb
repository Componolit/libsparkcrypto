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
procedure SHA256_Tests is
   SHA256_Ctx1, SHA256_Ctx2, SHA256_Ctx3  : LSC.SHA256.Context_Type;
   Hash1, Hash2, Hash3                    : LSC.SHA256.SHA256_Hash_Type;
   Message1, Message2, Message3           : LSC.SHA256.Block_Type;
begin

   LSC.Test.Suite ("SHA256 tests");

   --  FIPS 180-2, Appendix C: SHA-256 Examples

   --  C.1 SHA-256 Example (One-Block Message)
   SHA256_Ctx1 := LSC.SHA256.SHA256_Context_Init;
   Message1 := LSC.SHA256.Block_Type'(M (16#61626300#), others => 16#fedca987#);
   LSC.SHA256.Context_Finalize (SHA256_Ctx1, Message1, 24);
   Hash1 := LSC.SHA256.SHA256_Get_Hash (SHA256_Ctx1);

   LSC.Test.Run
     ("SHA-256 Example (One-Block Message)",
      Hash1 =
      LSC.SHA256.SHA256_Hash_Type'(M (16#ba7816bf#),
                                   M (16#8f01cfea#),
                                   M (16#414140de#),
                                   M (16#5dae2223#),
                                   M (16#b00361a3#),
                                   M (16#96177a9c#),
                                   M (16#b410ff61#),
                                   M (16#f20015ad#)));

   --  C.2 SHA-256 Example (Multi-Block Message)
   SHA256_Ctx2     := LSC.SHA256.SHA256_Context_Init;
   Message2 :=
     LSC.SHA256.Block_Type'(M (16#61626364#),
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

   LSC.SHA256.Context_Finalize (SHA256_Ctx2, Message2, 448);
   Hash2 := LSC.SHA256.SHA256_Get_Hash (SHA256_Ctx2);

   LSC.Test.Run
     ("SHA-256 Example (Multi-Block Message)",
      Hash2 =
      LSC.SHA256.SHA256_Hash_Type'(M (16#248d6a61#),
                                   M (16#d20638b8#),
                                   M (16#e5c02693#),
                                   M (16#0c3e6039#),
                                   M (16#a33ce459#),
                                   M (16#64ff2167#),
                                   M (16#f6ecedd4#),
                                   M (16#19db06c1#)));

   --  C.3 SHA-256 Example (Long Message)
   Message3 := LSC.SHA256.Block_Type'(others => M (16#61616161#));

   SHA256_Ctx3 := LSC.SHA256.SHA256_Context_Init;
   for I in Natural range 1 .. 15625
      --#  assert I in Natural;
   loop
      LSC.SHA256.Context_Update (SHA256_Ctx3, Message3);
   end loop;
   LSC.SHA256.Context_Finalize (SHA256_Ctx3, Message3, 0);
   Hash3 := LSC.SHA256.SHA256_Get_Hash (SHA256_Ctx3);

   LSC.Test.Run
     ("SHA-256 Example (Long Message)",
      Hash3 =
      LSC.SHA256.SHA256_Hash_Type'(M (16#cdc76e5c#),
                                   M (16#9914fb92#),
                                   M (16#81a1c7e2#),
                                   M (16#84d73e67#),
                                   M (16#f1809a48#),
                                   M (16#a497200e#),
                                   M (16#046d39cc#),
                                   M (16#c7112cd0#)));

end SHA256_Tests;
