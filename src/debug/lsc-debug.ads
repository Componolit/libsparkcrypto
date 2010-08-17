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

with LSC.Types;
--# inherit LSC.Types;

-------------------------------------------------------------------------------
-- Debug operations for printing text and basic types
-------------------------------------------------------------------------------
package LSC.Debug is

   -- Output string @T@
   procedure Put (T : String);
   --# derives null from T;
   pragma Inline (Put);

   -- Output the string @T@ followed by a line terminator
   procedure Put_Line (T : String);
   --# derives null from T;
   pragma Inline (Put_Line);

   -- Start a new line
   procedure New_Line;
   --# derives ;
   pragma Inline (New_Line);

   -- Output byte @I@
   procedure Print_Byte (I : in Types.Byte);
   --# derives null from I;
   pragma Inline (Print_Byte);

   -- Output 32-bit word @I@
   procedure Print_Word32 (I : in Types.Word32);
   --# derives null from I;
   pragma Inline (Print_Word32);

   -- Output the 64-bit word @I@
   procedure Print_Word64 (I : in Types.Word64);
   --# derives null from I;
   pragma Inline (Print_Word64);

   -- Output index @I@
   procedure Print_Index (I : in Types.Index);
   --# derives null from I;
   pragma Inline (Print_Index);

   -- Output natural number @I@
   procedure Print_Natural (I : in Natural);
   --# derives null from I;
   pragma Inline (Print_Natural);

   -- Output @Block@, an array of 32-bit words
   --
   -- @Space@ - Number of spaces to separate Word32 values <br>
   -- @Break@ - Insert a line terminator after @Break@ Word32 values <br>
   -- @Newln@ - Insert a line terminator after printing all Word32 values <br>
   --
   procedure Print_Word32_Array (Block : in Types.Word32_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean);
   --# derives null from Block, Space, Break, Newln;
   pragma Inline (Print_Word32_Array);

   -- Output @Block@, an array of 64-bit words
   --
   -- @Space@ - Number of spaces to separate Word64 values <br>
   -- @Break@ - Insert a line terminator after @Break@ Word64 values <br>
   -- @Newln@ - Insert a line terminator after printing all Word64 values <br>
   --
   procedure Print_Word64_Array (Block : in Types.Word64_Array_Type;
                                 Space : in Natural;
                                 Break : in Types.Index;
                                 Newln : in Boolean);
   --# derives null from Block, Space, Break, Newln;
   --# pre
   --#    Break > 0;
   pragma Inline (Print_Word64_Array);

end LSC.Debug;
