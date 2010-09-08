-------------------------------------------------------------------------------
-- This file is part of the sparkcrypto library.
--
-- Copyright (C) 2010  Alexander Senier <mail@senier.net>
-- Copyright (C) 2010  secunet Security Networks AG
--
-- libsparkcrypto is  free software; you  can redistribute it and/or  modify it
-- under  terms of  the GNU  General Public  License as  published by  the Free
-- Software  Foundation;  either version  3,  or  (at  your option)  any  later
-- version.  libsparkcrypto  is  distributed  in  the  hope  that  it  will  be
-- useful,  but WITHOUT  ANY WARRANTY;  without  even the  implied warranty  of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
--
-- As a  special exception under  Section 7 of GPL  version 3, you  are granted
-- additional  permissions  described in  the  GCC  Runtime Library  Exception,
-- version 3.1, as published by the Free Software Foundation.
--
-- You should  have received  a copy of  the GNU General  Public License  and a
-- copy  of  the  GCC  Runtime  Library  Exception  along  with  this  program;
-- see  the  files  COPYING3  and COPYING.RUNTIME  respectively.  If  not,  see
-- <http://www.gnu.org/licenses/>.
-------------------------------------------------------------------------------

with LSC.Byteorder64;

package body LSC.Pad64 is

   procedure Block_Terminate
     (Block  : in out Types.Word64_Array_Type;
      Length : in     Types.Word64)
   is
      pragma Inline (Block_Terminate);
      Temp   : Types.Word64;
      Index  : Types.Index;
      Offset : Natural;
   begin

      -- index of partial block
      Index := Types.Index'First + Types.Index (Length / 64);

      --# check Length = 0    -> Index =  0;
      --# check Length = 63   -> Index =  0;
      --# check Length = 64   -> Index =  1;
      --# check Length = 1023 -> Index = 15;

      -- bit offset within the partial block
      Offset := Natural (63 - Length mod 64);

      --# check Length = 0    -> Offset = 63;
      --# check Length = 63   -> Offset =  0;
      --# check Length = 64   -> Offset = 63;
      --# check Length = 1023 -> Offset =  0;

      Temp := Byteorder64.Native_To_BE (Block (Index));
      Temp := Temp and Types.SHL (not 0, Offset);
      Temp := Temp  or Types.SHL (1, Offset);
      Block (Index) := Byteorder64.BE_To_Native (Temp);

      if Index < Block'Last then
         for I in Types.Index range (Index + 1) .. Block'Last
         loop
            Block (I) := 0;
            --# assert
            --#    (for all P in Types.Index range
            --#       (Types.Index'First + Index + 1) .. I => (Block (P) = 0)) and
            --#    Index = Types.Index'First + Types.Index (Length / 64);
         end loop;
      end if;

   end Block_Terminate;

end LSC.Pad64;
