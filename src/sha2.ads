with Types;
--# inherit Types;

package SHA2 is

    type Hash_Context is private;

    type Block_Index is range 0 .. 15;
    type Block_Type is array (Block_Index) of Types.Word64;

    -- Initialize SHA2 context.
    function Context_Init return Hash_Context;

    -- Update SHA2 context with message block.
    procedure Context_Update
        (Context : in out Hash_Context;
         Block   : in     Block_Type);
    --# derives Context from *, Block;

    -- DEBUG

    procedure Context_Print (Context : Hash_Context);
    --# derives null from Context;

private

    type Message_Schedule_Index is range 0 .. 79;
    type Message_Schedule_Type is array (Message_Schedule_Index) of Types.Word64;

    type Hash_Context is
    record
        H0 : Types.Word64;
        H1 : Types.Word64;
        H2 : Types.Word64;
        H3 : Types.Word64;
        H4 : Types.Word64;
        H5 : Types.Word64;
        H6 : Types.Word64;
        H7 : Types.Word64;
    end record;

    function Ch
        (x : Types.Word64;
         y : Types.Word64;
         z : Types.Word64) return Types.Word64;

    function Maj
        (x : Types.Word64;
         y : Types.Word64;
         z : Types.Word64) return Types.Word64;

    function Cap_Sigma_0_512 (x : Types.Word64) return Types.Word64;
    function Cap_Sigma_1_512 (x : Types.Word64) return Types.Word64;
    function Sigma_0_512     (x : Types.Word64) return Types.Word64;
    function Sigma_1_512     (x : Types.Word64) return Types.Word64;

    K : constant Message_Schedule_Type := Message_Schedule_Type'
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

end SHA2;
