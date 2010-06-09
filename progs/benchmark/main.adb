--  This file is part of the sparkcrypto library.

--  Copyright (C) 2010  secunet Security Networks AG
--  Copyright (C) 2010  Alexander Senier <mail@senier.net>

--  This library  is free software:  you can  redistribute it and/or  modify it
--  under the  terms of the GNU  Lesser General Public License  as published by
--  the Free Software Foundation, either version  3 of the License, or (at your
--  option) any later version.

--  This library is distributed in the hope that it will be useful, but WITHOUT
--  ANY  WARRANTY; without  even  the implied  warranty  of MERCHANTABILITY  or
--  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
--  for more details.

--  You should  have received a copy  of the GNU Lesser  General Public License
--  along with this library. If not, see <http://www.gnu.org/licenses/>.

with LSC.SHA2;
with LSC.RIPEMD160;
with LSC.Types;
with OpenSSL;

with Ada.Text_IO; use Ada.Text_IO;
with Ada.Real_Time; use Ada.Real_Time;

use type LSC.Types.Word32_Array_Type;
use type LSC.Types.Word64_Array_Type;

procedure Main
is
   S1, S2  : Time;
   D1, D2  : Time_Span;
   Results : array (1 .. 1000) of Integer;

   function Result
      (Message   : String;
       Result    : Boolean;
       Duration1 : Time_Span;
       Duration2 : Time_Span) return Integer
   is
      Percent : Integer;
   begin
      Put (Message & ": ");
      if Result
      then
         Percent := (Time_Span (100 * Duration1) / Duration2);
         Put_Line (Percent'Img & " %");
      else
         Put_Line ("FAILED");
      end if;
      return Percent;
   end Result;

begin

   -- SHA384 benchmark
   declare
      Block1, Block2  : LSC.SHA2.Block_Type;
      SHA384_Context1 : OpenSSL.SHA384_Context_Type;
      SHA384_Context2 : LSC.SHA2.Context_Type;
      H1, H2          : LSC.SHA2.SHA384_Hash_Type;
   begin
      Block1  := LSC.SHA2.Block_Type'(others => 16#deadbeefcafebabe#);
      Block2  := LSC.SHA2.Block_Type'(others => 16#0000000000636261#);

      S1 := Clock;
      for I in 1 .. 100000
      loop
         OpenSSL.SHA384_Context_Init (SHA384_Context1);
         OpenSSL.SHA384_Context_Update (SHA384_Context1, Block1);
         OpenSSL.SHA384_Context_Finalize (SHA384_Context1, Block2, 56);
      end loop;
      H1 := OpenSSL.SHA384_Get_Hash (SHA384_Context1);
      D1 := Clock - S1;

      S2 := Clock;
      for I in 1 .. 100000
      loop
         SHA384_Context2 := LSC.SHA2.SHA384_Context_Init;
         LSC.SHA2.Context_Update (SHA384_Context2, Block1);
         LSC.SHA2.Context_Finalize (SHA384_Context2, Block2, 56);
      end loop;
      H2 := LSC.SHA2.SHA384_Get_Hash (SHA384_Context2);
      D2 := Clock - S2;

      Results (1) := Result ("   SHA384", H1 = H2, D1, D2);
   end;

   -- SHA512 benchmark
   declare
      Block1, Block2  : LSC.SHA2.Block_Type;
      SHA512_Context1 : OpenSSL.SHA512_Context_Type;
      SHA512_Context2 : LSC.SHA2.Context_Type;
      H1, H2          : LSC.SHA2.SHA512_Hash_Type;
   begin
      Block1  := LSC.SHA2.Block_Type'(others => 16#deadbeefcafebabe#);
      Block2  := LSC.SHA2.Block_Type'(others => 16#0000000000636261#);

      S1 := Clock;
      for I in 1 .. 100000
      loop
         OpenSSL.SHA512_Context_Init (SHA512_Context1);
         OpenSSL.SHA512_Context_Update (SHA512_Context1, Block1);
         OpenSSL.SHA512_Context_Finalize (SHA512_Context1, Block2, 56);
      end loop;
      H1 := OpenSSL.SHA512_Get_Hash (SHA512_Context1);
      D1 := Clock - S1;

      S2 := Clock;
      for I in 1 .. 100000
      loop
         SHA512_Context2 := LSC.SHA2.SHA512_Context_Init;
         LSC.SHA2.Context_Update (SHA512_Context2, Block1);
         LSC.SHA2.Context_Finalize (SHA512_Context2, Block2, 56);
      end loop;
      H2 := LSC.SHA2.SHA512_Get_Hash (SHA512_Context2);
      D2 := Clock - S2;

      Results (1) := Result ("   SHA512", H1 = H2, D1, D2);
   end;

   -- RIPEMD-160 benchmark
   declare
      Block1, Block2     : LSC.RIPEMD160.Block_Type;
      RIPEMD160_Context1 : OpenSSL.RIPEMD160_Context_Type;
      RIPEMD160_Context2 : LSC.RIPEMD160.Context_Type;
      H1, H2             : LSC.RIPEMD160.Hash_Type;
   begin
      Block1  := LSC.RIPEMD160.Block_Type'(others => 16#cafebabe#);
      Block2  := LSC.RIPEMD160.Block_Type'(others => 16#00636261#);

      S1 := Clock;
      for I in 1 .. 100000
      loop
         OpenSSL.RIPEMD160_Context_Init (RIPEMD160_Context1);
         OpenSSL.RIPEMD160_Context_Update (RIPEMD160_Context1, Block1);
         OpenSSL.RIPEMD160_Context_Finalize (RIPEMD160_Context1, Block2, 56);
      end loop;
      H1 := OpenSSL.RIPEMD160_Get_Hash (RIPEMD160_Context1);
      D1 := Clock - S1;

      S2 := Clock;
      for I in 1 .. 100000
      loop
         RIPEMD160_Context2 := LSC.RIPEMD160.Context_Init;
         LSC.RIPEMD160.Context_Update (RIPEMD160_Context2, Block1);
         LSC.RIPEMD160.Context_Finalize (RIPEMD160_Context2, Block2, 56);
      end loop;
      H2 := LSC.RIPEMD160.Get_Hash (RIPEMD160_Context2);
      D2 := Clock - S2;

      Results (1) := Result ("RIPEMD160", H1 = H2, D1, D2);
   end;

end Main;
