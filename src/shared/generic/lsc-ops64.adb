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

package body LSC.Ops64 is

   function Bytes_To_Word
      (Byte0 : Types.Byte;
       Byte1 : Types.Byte;
       Byte2 : Types.Byte;
       Byte3 : Types.Byte;
       Byte4 : Types.Byte;
       Byte5 : Types.Byte;
       Byte6 : Types.Byte;
       Byte7 : Types.Byte) return Types.Word64
   is
   begin
      return Types.Byte_Array64_To_Word64
          (Types.Byte_Array64_Type'(Byte7, Byte6, Byte5, Byte4,
                                    Byte3, Byte2, Byte1, Byte0));
   end Bytes_To_Word;

   ----------------------------------------------------------------------------

   function XOR2 (V0, V1 : Types.Word64) return Types.Word64
   is
   begin
      return V0 xor V1;
   end XOR2;

   ----------------------------------------------------------------------------

   procedure Block_XOR
     (Left   : in     Types.Word64_Array_Type;
      Right  : in     Types.Word64_Array_Type;
      Result :    out Types.Word64_Array_Type)
   is
   begin
      for I in Types.Index range Result'First .. Result'Last
      loop

         --# check
         --#    I <= Left'Last   and
         --#    I <= Right'Last  and
         --#    I <= Result'Last;

         --# accept Flow, 23, Result, "Initialized in complete loop";
         Result (I) := XOR2 (Left (I), Right (I));

         --# assert
         --#   (for all Pos in Types.Index range Result'First .. I =>
         --#       (Result (Pos) = XOR2 (Left (Pos), Right (Pos))));

      end loop;

      --# accept Flow, 602, Result, Result, "Initialized in complete loop";
   end Block_XOR;

   ----------------------------------------------------------------------------

   procedure Block_Copy
     (Source : in     Types.Word64_Array_Type;
      Dest   : in out Types.Word64_Array_Type)
   is
   begin

      for I in Types.Index range Source'First .. Source'Last
      loop
         --# check I in Source'Range;

         Dest (I) := Source (I);

         --# assert
         --#    (for all P in Types.Index range Source'First .. I =>
         --#        (Dest (P) = Source (P)));
      end loop;

   end Block_Copy;

end LSC.Ops64;
