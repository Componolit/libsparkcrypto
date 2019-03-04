-------------------------------------------------------------------------------
-- This file is part of libsparkcrypto.
--
-- @author Alexander Senier
-- @date   2019-01-22
--
-- Copyright (C) 2018 Componolit GmbH
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

with Ada.Unchecked_Conversion;

package body LSC.Ops_Generic
is
   ---------------
   -- Array_XOR --
   ---------------

   procedure Array_XOR
     (Left   : in     Left_Data_Type;
      Right  : in     Right_Data_Type;
      Result :    out Result_Data_Type)
   is
      type M8 is mod 2**8 with Size => 8;
      function To_M8 is new Ada.Unchecked_Conversion (Left_Elem_Type, M8);
      function To_M8 is new Ada.Unchecked_Conversion (Right_Elem_Type, M8);
      function From_M8 is new Ada.Unchecked_Conversion (M8, Result_Elem_Type);

   begin
      for I in 0 .. Left'Length - 1
       loop
         Result (Result_Index_Type'Val (Result_Index_Type'Pos (Result'First) + I)) :=
            From_M8 (To_M8 (Left (Left_Index_Type'Val (Left_Index_Type'Pos (Left'First) + I))) xor
                     To_M8 (Right (Right_Index_Type'Val (Right_Index_Type'Pos (Right'First) + I))));

         pragma Annotate (GNATprove, False_Positive, """Result"" might not be initialized",
                          "Initialized in complete loop in ""Array_XOR""");
      end loop;

      Result (Result_Index_Type'Val (Result_Index_Type'Pos (Result'First) + Left'Length) .. Result'Last)
         := (others => From_M8 (0));

      pragma Annotate (GNATprove, False_Positive, """Result"" might not be initialized",
                       "Initialized in complete loop in ""Array_XOR""");
   end Array_XOR;

end LSC.Ops_Generic;
