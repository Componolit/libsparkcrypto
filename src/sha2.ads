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

with Types;
--# inherit Types;

package SHA2 is

    type Context_Type is private;

    type Block_Index is range 0 .. 15;
    type Block_Type is array (Block_Index) of Types.Word64;

    type Hash_Index is range 0 .. 7;
    type Hash_Type is array (Hash_Index) of Types.Word64;

    subtype Block_Length_Type is Types.Word64 range 0 .. 1023;

    -- Initialize SHA2 context.
    function Context_Init return Context_Type;

    -- Update SHA2 context with message block.
    procedure Context_Update
        (Context : in out Context_Type;
         M       : in     Block_Type);
    --# derives
    --#    Context from *, M;

    -- Finalize SHA2 context with final message block.
    function Context_Finalize
        (Context : Context_Type;
         M       : Block_Type;
         Length  : Block_Length_Type) return Hash_Type;

private

    type Data_Length is
       record
          LSW : Types.Word64;
          MSW : Types.Word64;
       end record;

    type State_Index is (a, b, c, d, e, f, g, h);
    type State_Type is array (State_Index) of Types.Word64;

    type Schedule_Index is range 0 .. 79;
    type Schedule_Type is array (Schedule_Index) of Types.Word64;

    type Context_Type is
    record
        Length : Data_Length;
        H      : Hash_Type;
    end record;

    function Init_Data_Length return Data_Length;

    procedure Add (Item  : in out Data_Length;
                   Value : in     Types.Word64);
    --# derives Item from *, Value;

    procedure Block_Terminate
        (M      : in out Block_Type;
         Length : in Block_Length_Type);
    --# derives M from *, Length;

    function Ch
        (x : Types.Word64;
         y : Types.Word64;
         z : Types.Word64) return Types.Word64;
    --# return (x and y) xor ((not x) and z);

    function Maj
        (x : Types.Word64;
         y : Types.Word64;
         z : Types.Word64) return Types.Word64;
    --# return (x and y) xor (x and z) xor (y and z);

    function Cap_Sigma_0_512 (x : Types.Word64) return Types.Word64;
    function Cap_Sigma_1_512 (x : Types.Word64) return Types.Word64;
    function Sigma_0_512     (x : Types.Word64) return Types.Word64;
    function Sigma_1_512     (x : Types.Word64) return Types.Word64;

    K : constant Schedule_Type := Schedule_Type'
       (16#428a2f98d728ae22#, 16#7137449123ef65cd#, 16#b5c0fbcfec4d3b2f#, 16#e9b5dba58189dbbc#,
        16#3956c25bf348b538#, 16#59f111f1b605d019#, 16#923f82a4af194f9b#, 16#ab1c5ed5da6d8118#,
        16#d807aa98a3030242#, 16#12835b0145706fbe#, 16#243185be4ee4b28c#, 16#550c7dc3d5ffb4e2#,
        16#72be5d74f27b896f#, 16#80deb1fe3b1696b1#, 16#9bdc06a725c71235#, 16#c19bf174cf692694#,
        16#e49b69c19ef14ad2#, 16#efbe4786384f25e3#, 16#0fc19dc68b8cd5b5#, 16#240ca1cc77ac9c65#,
        16#2de92c6f592b0275#, 16#4a7484aa6ea6e483#, 16#5cb0a9dcbd41fbd4#, 16#76f988da831153b5#,
        16#983e5152ee66dfab#, 16#a831c66d2db43210#, 16#b00327c898fb213f#, 16#bf597fc7beef0ee4#,
        16#c6e00bf33da88fc2#, 16#d5a79147930aa725#, 16#06ca6351e003826f#, 16#142929670a0e6e70#,
        16#27b70a8546d22ffc#, 16#2e1b21385c26c926#, 16#4d2c6dfc5ac42aed#, 16#53380d139d95b3df#,
        16#650a73548baf63de#, 16#766a0abb3c77b2a8#, 16#81c2c92e47edaee6#, 16#92722c851482353b#,
        16#a2bfe8a14cf10364#, 16#a81a664bbc423001#, 16#c24b8b70d0f89791#, 16#c76c51a30654be30#,
        16#d192e819d6ef5218#, 16#d69906245565a910#, 16#f40e35855771202a#, 16#106aa07032bbd1b8#,
        16#19a4c116b8d2d0c8#, 16#1e376c085141ab53#, 16#2748774cdf8eeb99#, 16#34b0bcb5e19b48a8#,
        16#391c0cb3c5c95a63#, 16#4ed8aa4ae3418acb#, 16#5b9cca4f7763e373#, 16#682e6ff3d6b2b8a3#,
        16#748f82ee5defb2fc#, 16#78a5636f43172f60#, 16#84c87814a1f0ab72#, 16#8cc702081a6439ec#,
        16#90befffa23631e28#, 16#a4506cebde82bde9#, 16#bef9a3f7b2c67915#, 16#c67178f2e372532b#,
        16#ca273eceea26619c#, 16#d186b8c721c0c207#, 16#eada7dd6cde0eb1e#, 16#f57d4f7fee6ed178#,
        16#06f067aa72176fba#, 16#0a637dc5a2c898a6#, 16#113f9804bef90dae#, 16#1b710b35131c471b#,
        16#28db77f523047d84#, 16#32caab7b40c72493#, 16#3c9ebe0a15c9bebc#, 16#431d67c49c100d4c#,
        16#4cc5d4becb3e42b6#, 16#597f299cfc657e2a#, 16#5fcb6fab3ad6faec#, 16#6c44198c4a475817#);

    procedure Context_Update_Internal
        (Context : in out Context_Type;
         M       : in     Block_Type);
    --# derives Context from *, M;

end SHA2;
