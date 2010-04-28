with SHA2;
--# inherit SHA2;

--# main_program;
procedure Test_SHA2
--# derives ;
is
    Ctx : SHA2.Hash_Context;
begin

    --# accept Flow, 10, "Still testing";
    Ctx := SHA2.Context_Init;

    --# accept Flow, 10, Ctx, "Still testing";
    SHA2.Context_Update
        (Ctx,
         SHA2.Block_Type'(16#6162638000000000#, others => 0));

end Test_SHA2;
