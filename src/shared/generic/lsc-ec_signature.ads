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
with LSC.Bignum;
with LSC.EC;
with LSC.Math_Int;

use type LSC.Math_Int.Math_Int;
use type LSC.Types.Word32;

package LSC.EC_Signature
is

   type Signature_Type is (ECDSA, ECGDSA);

   procedure Sign
     (Sign1       :    out Bignum.Big_Int;
      Sign1_First : in     Natural;
      Sign1_Last  : in     Natural;
      Sign2       :    out Bignum.Big_Int;
      Sign2_First : in     Natural;
      Hash        : in     Bignum.Big_Int;
      Hash_First  : in     Natural;
      Rand        : in     Bignum.Big_Int;
      Rand_First  : in     Natural;
      T           : in     Signature_Type;
      Priv        : in     Bignum.Big_Int;
      Priv_First  : in     Natural;
      BX          : in     Bignum.Big_Int;
      BX_First    : in     Natural;
      BY          : in     Bignum.Big_Int;
      BY_First    : in     Natural;
      A           : in     Bignum.Big_Int;
      A_First     : in     Natural;
      M           : in     Bignum.Big_Int;
      M_First     : in     Natural;
      M_Inv       : in     Types.Word32;
      RM          : in     Bignum.Big_Int;
      RM_First    : in     Natural;
      N           : in     Bignum.Big_Int;
      N_First     : in     Natural;
      N_Inv       : in     Types.Word32;
      RN          : in     Bignum.Big_Int;
      RN_First    : in     Natural;
      Success     :    out Boolean)
     with
       Depends =>
         (Sign1 =>+
            (Sign1_First, Sign1_Last, Rand, Rand_First,
             BX, BX_First, BY, BY_First, A, A_First,
             M, M_First, M_Inv, RM, RM_First,
             N, N_First, N_Inv, RN, RN_First),
          (Sign2, Success) =>
            (Sign1, Sign1_First, Sign1_Last, Sign2, Sign2_First,
             Hash, Hash_First, Rand, Rand_First,
             T, Priv, Priv_First, BX, BX_First, BY, BY_First, A, A_First,
             M, M_First, M_Inv, RM, RM_First,
             N, N_First, N_Inv, RN, RN_First)),
       Pre =>
         Sign1_First in Sign1'Range and
         Sign1_Last in Sign1'Range and
         Sign1_First < Sign1_Last and
         Sign1_Last - Sign1_First < EC.Max_Coord_Length and
         Sign2_First in Sign2'Range and
         Sign2_First + (Sign1_Last - Sign1_First) in Sign2'Range and
         Hash_First in Hash'Range and
         Hash_First + (Sign1_Last - Sign1_First) in Hash'Range and
         Rand_First in Rand'Range and
         Rand_First + (Sign1_Last - Sign1_First) in Rand'Range and
         Priv_First in Priv'Range and
         Priv_First + (Sign1_Last - Sign1_First) in Priv'Range and
         BX_First in BX'Range and
         BX_First + (Sign1_Last - Sign1_First) in BX'Range and
         BY_First in BY'Range and
         BY_First + (Sign1_Last - Sign1_First) in BY'Range and
         A_First in A'Range and
         A_First + (Sign1_Last - Sign1_First) in A'Range and
         M_First in M'Range and
         M_First + (Sign1_Last - Sign1_First) in M'Range and
         RM_First in RM'Range and
         RM_First + (Sign1_Last - Sign1_First) in RM'Range and
         N_First in N'Range and
         N_First + (Sign1_Last - Sign1_First) in N'Range and
         RN_First in RN'Range and
         RN_First + (Sign1_Last - Sign1_First) in RN'Range and
         Bignum.Num_Of_Big_Int (BX, BX_First, Sign1_Last - Sign1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, Sign1_Last - Sign1_First + 1) and
         Bignum.Num_Of_Big_Int (BY, BY_First, Sign1_Last - Sign1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, Sign1_Last - Sign1_First + 1) and
         Bignum.Num_Of_Big_Int (A, A_First, Sign1_Last - Sign1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, Sign1_Last - Sign1_First + 1) and
         Math_Int.From_Word32 (1) <
         Bignum.Num_Of_Big_Int (M, M_First, Sign1_Last - Sign1_First + 1) and
         1 + M_Inv * M (M_First) = 0 and
         Math_Int.From_Word32 (1) <
         Bignum.Num_Of_Big_Int (N, N_First, Sign1_Last - Sign1_First + 1) and
         1 + N_Inv * N (N_First) = 0 and
         Bignum.Num_Of_Big_Int (RM, RM_First, Sign1_Last - Sign1_First + 1) =
         Bignum.Base ** (2 * (Sign1_Last - Sign1_First + 1)) mod
         Bignum.Num_Of_Big_Int (M, M_First, Sign1_Last - Sign1_First + 1) and
         Bignum.Num_Of_Big_Int (RN, RN_First, Sign1_Last - Sign1_First + 1) =
         Bignum.Base ** (2 * (Sign1_Last - Sign1_First + 1)) mod
         Bignum.Num_Of_Big_Int (N, N_First, Sign1_Last - Sign1_First + 1),
       Post =>
         (if Success then
            (Math_Int.From_Word32 (0) < Bignum.Num_Of_Big_Int
               (Sign1, Sign1_First, Sign1_Last - Sign1_First + 1) and
             Bignum.Num_Of_Big_Int
               (Sign1, Sign1_First, Sign1_Last - Sign1_First + 1) <
             Bignum.Num_Of_Big_Int (N, N_First, Sign1_Last - Sign1_First + 1) and
             Math_Int.From_Word32 (0) < Bignum.Num_Of_Big_Int
               (Sign2, Sign2_First, Sign1_Last - Sign1_First + 1) and
             Bignum.Num_Of_Big_Int
               (Sign2, Sign2_First, Sign1_Last - Sign1_First + 1) <
             Bignum.Num_Of_Big_Int (N, N_First, Sign1_Last - Sign1_First + 1)));

   function Verify
     (Sign1       : Bignum.Big_Int;
      Sign1_First : Natural;
      Sign1_Last  : Natural;
      Sign2       : Bignum.Big_Int;
      Sign2_First : Natural;
      Hash        : Bignum.Big_Int;
      Hash_First  : Natural;
      T           : Signature_Type;
      PubX        : Bignum.Big_Int;
      PubX_First  : Natural;
      PubY        : Bignum.Big_Int;
      PubY_First  : Natural;
      BX          : Bignum.Big_Int;
      BX_First    : Natural;
      BY          : Bignum.Big_Int;
      BY_First    : Natural;
      A           : Bignum.Big_Int;
      A_First     : Natural;
      M           : Bignum.Big_Int;
      M_First     : Natural;
      M_Inv       : Types.Word32;
      RM          : Bignum.Big_Int;
      RM_First    : Natural;
      N           : Bignum.Big_Int;
      N_First     : Natural;
      N_Inv       : Types.Word32;
      RN          : Bignum.Big_Int;
      RN_First    : Natural)
     return Boolean
     with
       Pre =>
         Sign1_First in Sign1'Range and
         Sign1_Last in Sign1'Range and
         Sign1_First < Sign1_Last and
         Sign1_Last - Sign1_First < EC.Max_Coord_Length and
         Sign2_First in Sign2'Range and
         Sign2_First + (Sign1_Last - Sign1_First) in Sign2'Range and
         Hash_First in Hash'Range and
         Hash_First + (Sign1_Last - Sign1_First) in Hash'Range and
         PubX_First in PubX'Range and
         PubX_First + (Sign1_Last - Sign1_First) in PubX'Range and
         PubY_First in PubY'Range and
         PubY_First + (Sign1_Last - Sign1_First) in PubY'Range and
         BX_First in BX'Range and
         BX_First + (Sign1_Last - Sign1_First) in BX'Range and
         BY_First in BY'Range and
         BY_First + (Sign1_Last - Sign1_First) in BY'Range and
         A_First in A'Range and
         A_First + (Sign1_Last - Sign1_First) in A'Range and
         M_First in M'Range and
         M_First + (Sign1_Last - Sign1_First) in M'Range and
         RM_First in RM'Range and
         RM_First + (Sign1_Last - Sign1_First) in RM'Range and
         N_First in N'Range and
         N_First + (Sign1_Last - Sign1_First) in N'Range and
         RN_First in RN'Range and
         RN_First + (Sign1_Last - Sign1_First) in RN'Range and
         Bignum.Num_Of_Big_Int (PubX, PubX_First, Sign1_Last - Sign1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, Sign1_Last - Sign1_First + 1) and
         Bignum.Num_Of_Big_Int (PubY, PubY_First, Sign1_Last - Sign1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, Sign1_Last - Sign1_First + 1) and
         Bignum.Num_Of_Big_Int (BX, BX_First, Sign1_Last - Sign1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, Sign1_Last - Sign1_First + 1) and
         Bignum.Num_Of_Big_Int (BY, BY_First, Sign1_Last - Sign1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, Sign1_Last - Sign1_First + 1) and
         Bignum.Num_Of_Big_Int (A, A_First, Sign1_Last - Sign1_First + 1) <
         Bignum.Num_Of_Big_Int (M, M_First, Sign1_Last - Sign1_First + 1) and
         Math_Int.From_Word32 (1) <
         Bignum.Num_Of_Big_Int (M, M_First, Sign1_Last - Sign1_First + 1) and
         1 + M_Inv * M (M_First) = 0 and
         Math_Int.From_Word32 (1) <
         Bignum.Num_Of_Big_Int (N, N_First, Sign1_Last - Sign1_First + 1) and
         1 + N_Inv * N (N_First) = 0 and
         Bignum.Num_Of_Big_Int (RM, RM_First, Sign1_Last - Sign1_First + 1) =
         Bignum.Base ** (2 * (Sign1_Last - Sign1_First + 1)) mod
         Bignum.Num_Of_Big_Int (M, M_First, Sign1_Last - Sign1_First + 1) and
         Bignum.Num_Of_Big_Int (RN, RN_First, Sign1_Last - Sign1_First + 1) =
         Bignum.Base ** (2 * (Sign1_Last - Sign1_First + 1)) mod
         Bignum.Num_Of_Big_Int (N, N_First, Sign1_Last - Sign1_First + 1);

end LSC.EC_Signature;
