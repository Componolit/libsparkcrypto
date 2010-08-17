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

package body LSC.Debug is

   procedure Put (T : String)
   is
      pragma Unreferenced (T);
   begin
      --# accept Flow, 30, T, "Null implementation";
      null;
   end Put;

   ----------------------------------------------------------------------------

   procedure Put_Line (T : String)
   is
      pragma Unreferenced (T);
   begin
      --# accept Flow, 30, T, "Null implementation";
      null;
   end Put_Line;

   ----------------------------------------------------------------------------

   procedure New_Line is
   begin
      null;
   end New_Line;

   ----------------------------------------------------------------------------

   procedure Print_Byte (I : in Types.Byte)
   is
      pragma Unreferenced (I);
   begin
      --# accept Flow, 30, I, "Null implementation";
      null;
   end Print_Byte;

   ----------------------------------------------------------------------------

   procedure Print_Word32 (I : in Types.Word32)
   is
      pragma Unreferenced (I);
   begin
      --# accept Flow, 30, I, "Null implementation";
      null;
   end Print_Word32;

   ----------------------------------------------------------------------------

   procedure Print_Word64 (I : in Types.Word64)
   is
      pragma Unreferenced (I);
   begin
      --# accept Flow, 30, I, "Null implementation";
      null;
   end Print_Word64;

   ----------------------------------------------------------------------------

   procedure Print_Index (I : in Types.Index)
   is
      pragma Unreferenced (I);
   begin
      --# accept Flow, 30, I, "Null implementation";
      null;
   end Print_Index;

   ----------------------------------------------------------------------------

   procedure Print_Natural (I : in Natural)
   is
      pragma Unreferenced (I);
   begin
      --# accept Flow, 30, I, "Null implementation";
      null;
   end Print_Natural;

   ----------------------------------------------------------------------------

   procedure Print_Word32_Array (Block : in Types.Word32_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean)
   is
      pragma Unreferenced (Block, Space, Break, Newln);
   begin
      --# accept Flow, 30, Block, "Null implementation" &
      --#        Flow, 30, Space, "Null implementation" &
      --#        Flow, 30, Break, "Null implementation" &
      --#        Flow, 30, Newln, "Null implementation";
      null;
   end Print_Word32_Array;

   ----------------------------------------------------------------------------

   procedure Print_Word64_Array (Block : in Types.Word64_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean)
   is
      pragma Unreferenced (Block, Space, Break, Newln);
   begin
      --# accept Flow, 30, Block, "Null implementation" &
      --#        Flow, 30, Space, "Null implementation" &
      --#        Flow, 30, Break, "Null implementation" &
      --#        Flow, 30, Newln, "Null implementation";
      null;
   end Print_Word64_Array;

end LSC.Debug;
