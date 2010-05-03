with SHA2, HMAC.SHA512, Test;
--# inherit SHA2,HMAC.SHA512, Test;

use type SHA2.Hash_Type;

procedure Main
is
    Context             : HMAC.SHA512.Context_Type;
    Key                 : SHA2.Block_Type;
    Block               : SHA2.Block_Type;
    PRF_HMAC_SHA_512    : SHA2.Hash_Type;
begin

    --  SHA512 Authentication Test Vectors (RFC 4868, 2.7.2.3.)

    --  Test Case AUTH512-1:

    Key := SHA2.Block_Type'(others => 16#0b_0b_0b_0b_0b_0b_0b_0b#);
    Block := SHA2.Block_Type'(16#48_69_20_54_68_65_72_65#, others => 0);

    Context := HMAC.SHA512.Init (Key);
    HMAC.SHA512.Update (Context, Block);
    HMAC.SHA512.Finalize (Context, Block, 0);
    PRF_HMAC_SHA_512 := HMAC.SHA512.Get_PRF (Context);

    Test.Run ("AUTH512-1",
              PRF_HMAC_SHA_512 = SHA2.Hash_Type'(16#637edc6e01dce7e6#, 16#742a99451aae82df#,
                                                 16#23da3e92439e590e#, 16#43e761b33e910fb8#,
                                                 16#ac2878ebd5803f6f#, 16#0b61dbce5e251ff8#,
                                                 16#789a4722c1be65ae#, 16#a45fd464e89f8f5b#));
end Main;
