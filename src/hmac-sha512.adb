--  This file is part of the sparkcrypto library.
--
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

package body HMAC.SHA512 is

    IPad : constant SHA2.Block_Type := (others => 16#36363636_36363636#);
    OPad : constant SHA2.Block_Type := (others => 16#5C5C5C5C_5C5C5C5C#);

    function Init (Key : SHA2.Block_Type) return Context_Type
    is
        Result : Context_Type;
    begin
        Result.Key            := Key;
        Result.SHA512_Context := SHA2.Context_Init;
        SHA2.Context_Update (Result.SHA512_Context, Block_XOR (Result.Key, IPad));
        return Result;
    end Init;

    procedure Update
        (Context : in out Context_Type;
         Block   : in     SHA2.Block_Type)
    is
    begin
        SHA2.Context_Update (Context.SHA512_Context, Block);
    end Update;

    procedure Finalize
        (Context : in out Context_Type;
         Block   : in     SHA2.Block_Type;
         Length  : in     SHA2.Block_Length_Type)
    is
    begin
        SHA2.Context_Finalize (Context.SHA512_Context, Block, Length);
        SHA2.Context_Update (Context.SHA512_Context, Block_XOR (Context.Key, OPad));
    end Finalize;

    function Get_Prf (Context : in Context_Type) return SHA2.Hash_Type
    is
    begin
        return SHA2.Get_Hash (Context.SHA512_Context);
    end Get_Prf;

end HMAC.SHA512;
