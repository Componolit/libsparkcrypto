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

with SHA2;
--# inherit SHA2;

package HMAC.SHA512 is

    type Context_Type is private;

    function Init (Key : SHA2.Block_Type) return Context_Type;

    procedure Update
        (Context : in out Context_Type;
         Block   : in     SHA2.Block_Type);
    --# derives Context from *, block;

    procedure Finalize
        (Context : in out Context_Type;
         Block   : in     SHA2.Block_Type;
         Length  : in     SHA2.Block_Length_Type);

private

    type Context_Type is
    record
        SHA512_Context : SHA2.Context_Type;
        Key            : SHA2.Block_Type;
    end record;

end HMAC.SHA512;
