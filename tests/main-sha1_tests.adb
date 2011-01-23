-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2011, Adrian-Ken Rueegsegger
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
procedure SHA1_Tests is
   SHA1_Suite                      : SPARKUnit.Index_Type;
   SHA1_Ctx1, SHA1_Ctx2, SHA1_Ctx3 : LSC.SHA1.Context_Type;
   Hash1, Hash2, Hash3             : LSC.SHA1.Hash_Type;
   Message1, Message2, Message3    : LSC.SHA1.Block_Type;
begin

   SPARKUnit.Create_Suite (Harness, "SHA-1 tests", SHA1_Suite);

   --  FIPS 180-2, Appendix A: SHA-1 Examples

   --  A.1 SHA-1 Example (One-Block Message)
   SHA1_Ctx1 := LSC.SHA1.Context_Init;
   Message1  := LSC.SHA1.Block_Type'(M (16#61626300#), others => 16#fedca987#);
   LSC.SHA1.Context_Finalize (SHA1_Ctx1, Message1, 24);
   Hash1 := LSC.SHA1.Get_Hash (SHA1_Ctx1);

   SPARKUnit.Create_Test
     (Harness,
      SHA1_Suite,
      "SHA-1 Example (One-Block Message)",
      Hash1 = LSC.SHA1.Hash_Type'
        (M (16#a9993e36#), M (16#4706816a#), M (16#ba3e2571#),
         M (16#7850c26c#), M (16#9cd0d89d#)));

   --  A.2 SHA-1 Example (Multi-Block Message)
   SHA1_Ctx2 := LSC.SHA1.Context_Init;
   Message2  := LSC.SHA1.Block_Type'
     (M (16#61626364#), M (16#62636465#), M (16#63646566#), M (16#64656667#),
      M (16#65666768#), M (16#66676869#), M (16#6768696a#), M (16#68696a6b#),
      M (16#696a6b6c#), M (16#6a6b6c6d#), M (16#6b6c6d6e#), M (16#6c6d6e6f#),
      M (16#6d6e6f70#), M (16#6e6f7071#), M (16#0a000000#),
      others => 16#deadbeef#);

   LSC.SHA1.Context_Finalize (SHA1_Ctx2, Message2, 448);
   Hash2 := LSC.SHA1.Get_Hash (SHA1_Ctx2);

   SPARKUnit.Create_Test
     (Harness,
      SHA1_Suite,
      "SHA-1 Example (Multi-Block Message)",
      Hash2 = LSC.SHA1.Hash_Type'
        (M (16#84983e44#), M (16#1c3bd26e#), M (16#baae4aa1#),
         M (16#f95129e5#), M (16#e54670f1#)));

   --  A.3 SHA-1 Example (Long Message)
   Message3 := LSC.SHA1.Block_Type'(others => M (16#61616161#));

   SHA1_Ctx3 := LSC.SHA1.Context_Init;
   for I in Natural range 1 .. 15625
   --#  assert I in Natural;
   loop
      LSC.SHA1.Context_Update (SHA1_Ctx3, Message3);
   end loop;
   LSC.SHA1.Context_Finalize (SHA1_Ctx3, Message3, 0);
   Hash3 := LSC.SHA1.Get_Hash (SHA1_Ctx3);

   SPARKUnit.Create_Test
     (Harness,
      SHA1_Suite,
      "SHA-1 Example (Long Message)",
      Hash3 = LSC.SHA1.Hash_Type'
        (M (16#34aa973c#), M (16#d4c4daa4#), M (16#f61eeb2b#),
         M (16#dbad2731#), M (16#6534016f#)));

end SHA1_Tests;
