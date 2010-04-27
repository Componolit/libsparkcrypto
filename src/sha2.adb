with Types;
use type Types.Word64;

package body SHA2 is

    function Ch
        (x : Types.Word64;
         y : Types.Word64;
         z : Types.Word64) return Types.Word64
    is
    begin
        return ((x and y) xor ((not x) and z));
    end Ch;

    function Maj
        (x : Types.Word64;
         y : Types.Word64;
         z : Types.Word64) return Types.Word64
    is
    begin
        return (x and y) xor (x and z) xor (y and z);
    end Maj;

    function Cap_Sigma_0_512 (x : Types.Word64) return Types.Word64
    is
    begin
        return Types.ROTR (x, 28) + Types.ROTR (x, 34) + Types.ROTR (x, 39);
    end Cap_Sigma_0_512;

    function Cap_Sigma_1_512 (x : Types.Word64) return Types.Word64
    is
    begin
        return Types.ROTR (x, 14) + Types.ROTR (x, 18) + Types.ROTR (x, 41);
    end Cap_Sigma_1_512;

    function Sigma_0_512     (x : Types.Word64) return Types.Word64
    is
    begin
        return Types.ROTR (x, 1) + Types.ROTR (x, 8) + Types.SHR (x, 7);
    end Sigma_0_512;

    function Sigma_1_512     (x : Types.Word64) return Types.Word64
    is
    begin
        return Types.ROTR (x, 19) + Types.ROTR (x, 61) + Types.SHR (x, 6);
    end Sigma_1_512;

    function Context_Init return Hash_Context
    is
    begin
        return Hash_Context'
            (H0 => 16#6a09e667f3bcc908#,
             H1 => 16#bb67ae8584caa73b#,
             H2 => 16#3c6ef372fe94f82b#,
             H3 => 16#a54ff53a5f1d36f1#,
             H4 => 16#510e527fade682d1#,
             H5 => 16#9b05688c2b3e6c1f#,
             H6 => 16#1f83d9abfb41bd6b#,
             H7 => 16#5be0cd19137e2179#);
    end Context_Init;

    procedure Context_Update
        (Context : in out Hash_Context;
         Block   : in     Block_Type)
    is
        W                               : Message_Schedule_Type;
        a, b, c, d, e, f, g, h, T1, T2  : Types.Word64;
    begin

        W := Message_Schedule_Type'(others => 0);

        -------------------------------------------
        --  Section 6.3.2 SHA-512 Hash Computations
        -------------------------------------------

        --  1. Prepare the message schedule, W(t):
        for t in Message_Schedule_Index range 0 .. 79
            --# assert t in 0 .. 79;
        loop
            if 0 <= t and t <= 15
            then
                W (t) := Block (Block_Index (t));
            end if;

            if 16 <= t and t <= 79
            then
                W (t) := Sigma_1_512 (W (t - 2)) +
                         W (t - 7) +
                         Sigma_0_512 (W (t - 15)) +
                         W (t - 16);
            end if;
        end loop;

        -- 2. Initialize the eight working variables a, b, c, d, e, f, g, and
        --    h with the (i-1)st hash value:
        a := Context.H0;
        b := Context.H1;
        c := Context.H2;
        d := Context.H3;
        e := Context.H4;
        f := Context.H5;
        g := Context.H6;
        h := Context.H7;

        -- 3. For t = 0 to 79:
        for t in Message_Schedule_Index range 0 .. 79
            --# assert t in 0 .. 79;
        loop
            T1 := h + Cap_Sigma_1_512 (e) + Ch (e, f, g) + K (t) + W (t);
            T2 := Cap_Sigma_0_512 (a) + Maj (a, b, c);
             h := g;
             g := f;
             f := e;
             e := d + T1;
             d := c;
             c := b;
             b := a;
             a := T1 + T2;
        end loop;

        -- 4. Compute the i-th intermediate hash value H-i:
        Context.H0 := a + Context.H0;
        Context.H1 := b + Context.H1;
        Context.H2 := c + Context.H2;
        Context.H3 := d + Context.H3;
        Context.H4 := e + Context.H4;
        Context.H5 := f + Context.H5;
        Context.H6 := g + Context.H6;
        Context.H7 := h + Context.H7;

    end Context_Update;

    procedure Context_Print (Context : Hash_Context)
    is
    begin
        null;
    end Context_Print;

end SHA2;
