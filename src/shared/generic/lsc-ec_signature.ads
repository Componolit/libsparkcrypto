-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- Copyright (C) 2012, Stefan Berghofer
-- Copyright (C) 2012, secunet Security Networks AG
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
--    * Neither the name of the author nor the names of its contributors may be
--      used to endorse or promote products derived from this software without
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

with LSC.Types;
with LSC.EC;

--# inherit
--#   LSC.Types,
--#   LSC.Bignum,
--#   LSC.EC;

package LSC.EC_Signature
is

   type Signature_Type is (ECDSA, ECGDSA);

   procedure Sign
     (Sign1   :    out EC.Coord;
      Sign2   :    out EC.Coord;
      Hash    : in     EC.Coord;
      Rand    : in     EC.Coord;
      T       : in     Signature_Type;
      Priv    : in     EC.Coord;
      BX      : in     EC.Coord;
      BY      : in     EC.Coord;
      A       : in     EC.Coord;
      M       : in     EC.Coord;
      M_Inv   : in     Types.Word32;
      RM      : in     EC.Coord;
      N       : in     EC.Coord;
      N_Inv   : in     Types.Word32;
      RN      : in     EC.Coord;
      Success :    out Boolean);
   --# derives
   --#   Sign1 from
   --#     Rand, BX, BY, A, M, M_Inv, RM, N, N_Inv, RN &
   --#   Sign2, Success from
   --#     Hash, Rand, T, Priv, BX, BY, A, M, M_Inv, RM, N, N_Inv, RN;
   --# pre
   --#   Bignum.Num_Of_Big_Int (Hash, Hash'First, Hash'Length) <
   --#   Bignum.Num_Of_Big_Int (N, N'First, N'Length) and
   --#   Bignum.Num_Of_Big_Int (BX, BX'First, BX'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (BY, BY'First, BY'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (A, A'First, A'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 < Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 + M_Inv * M (M'First) = 0 and
   --#   1 < Bignum.Num_Of_Big_Int (N, N'First, M'Length) and
   --#   1 + N_Inv * N (N'First) = 0 and
   --#   Bignum.Num_Of_Big_Int (RM, RM'First, RM'Length) =
   --#   Bignum.Base ** (2 * RM'Length) mod
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (RN, RN'First, RN'Length) =
   --#   Bignum.Base ** (2 * RN'Length) mod
   --#   Bignum.Num_Of_Big_Int (N, N'First, N'Length);
   --# post
   --#   Success ->
   --#     (0 < Bignum.Num_Of_Big_Int (Sign1, Sign1'First, Sign1'Length) and
   --#      Bignum.Num_Of_Big_Int (Sign1, Sign1'First, Sign1'Length) <
   --#      Bignum.Num_Of_Big_Int (N, N'First, N'Length) and
   --#      0 < Bignum.Num_Of_Big_Int (Sign2, Sign2'First, Sign2'Length) and
   --#      Bignum.Num_Of_Big_Int (Sign2, Sign2'First, Sign2'Length) <
   --#      Bignum.Num_Of_Big_Int (N, N'First, N'Length));

   function Verify
     (Sign1 : EC.Coord;
      Sign2 : EC.Coord;
      Hash  : EC.Coord;
      T     : Signature_Type;
      PubX  : EC.Coord;
      PubY  : EC.Coord;
      BX    : EC.Coord;
      BY    : EC.Coord;
      A     : EC.Coord;
      M     : EC.Coord;
      M_Inv : Types.Word32;
      RM    : EC.Coord;
      N     : EC.Coord;
      N_Inv : Types.Word32;
      RN    : EC.Coord)
     return Boolean;
   --# pre
   --#   Bignum.Num_Of_Big_Int (PubX, PubX'First, PubX'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (PubY, PubY'First, PubY'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (BX, BX'First, BX'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (BY, BY'First, BY'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (A, A'First, A'Length) <
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 < Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   1 + M_Inv * M (M'First) = 0 and
   --#   1 < Bignum.Num_Of_Big_Int (N, N'First, M'Length) and
   --#   1 + N_Inv * N (N'First) = 0 and
   --#   Bignum.Num_Of_Big_Int (RM, RM'First, RM'Length) =
   --#   Bignum.Base ** (2 * RM'Length) mod
   --#   Bignum.Num_Of_Big_Int (M, M'First, M'Length) and
   --#   Bignum.Num_Of_Big_Int (RN, RN'First, RN'Length) =
   --#   Bignum.Base ** (2 * RN'Length) mod
   --#   Bignum.Num_Of_Big_Int (N, N'First, N'Length);

end LSC.EC_Signature;
