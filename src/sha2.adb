with Types, SHA2.Debug;
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

    function Context_Init return Context_Type
    is
    begin
        return Context_Type'
            (H => Hash_Type'(0 => 16#6a09e667f3bcc908#,
                             1 => 16#bb67ae8584caa73b#,
                             2 => 16#3c6ef372fe94f82b#,
                             3 => 16#a54ff53a5f1d36f1#,
                             4 => 16#510e527fade682d1#,
                             5 => 16#9b05688c2b3e6c1f#,
                             6 => 16#1f83d9abfb41bd6b#,
                             7 => 16#5be0cd19137e2179#));
    end Context_Init;

    procedure Context_Update
        (Context : in out Context_Type;
         Block   : in     Block_Type)
    is
        W      : Schedule_Type;
        S      : State_Type;
        T1, T2 : Types.Word64;
    begin

        W := Schedule_Type'(others => 0);

        -- Print out initial state of H
        Debug.Put_Hash (Context.H);

        -------------------------------------------
        --  Section 6.3.2 SHA-512 Hash Computations
        -------------------------------------------

        --  1. Prepare the message schedule, W(t):
        for t in Schedule_Index range 0 .. 79
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

        Debug.Put_Schedule (W);

        -- 2. Initialize the eight working variables a, b, c, d, e, f, g, and
        --    h with the (i-1)st hash value:
        S := State_Type'(a => Context.H (0),
                         b => Context.H (1),
                         c => Context.H (2),
                         d => Context.H (3),
                         e => Context.H (4),
                         f => Context.H (5),
                         g => Context.H (6),
                         h => Context.H (7));

        -- 3. For t = 0 to 79:
        for t in Schedule_Index range 0 .. 79
            --# assert t in 0 .. 79;
        loop
            T1 := S (h) + Cap_Sigma_1_512 (S (e)) + Ch (S (e), S (f), S (g)) + K (t) + W (t);
            T2 := Cap_Sigma_0_512 (S (a)) + Maj (S (a), S (b), S (c));

             S := State_Type'(h => S (g),
                              g => S (f),
                              f => S (e),
                              e => S (d) + T1,
                              d => S (c),
                              c => S (b),
                              b => S (a),
                              a => T1 + T2);

            Debug.Put_State (S);

        end loop;

        -- 4. Compute the i-th intermediate hash value H-i:
        Context.H := Hash_Type'(0 => S (a) + Context.H (0),
                                1 => S (b) + Context.H (1),
                                2 => S (c) + Context.H (2),
                                3 => S (d) + Context.H (3),
                                4 => S (e) + Context.H (4),
                                5 => S (f) + Context.H (5),
                                6 => S (g) + Context.H (6),
                                7 => S (h) + Context.H (7));

    end Context_Update;

end SHA2;
