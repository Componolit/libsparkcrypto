with SHA2;
--# inherit SHA2;

--# main_program;
procedure Test_SHA2
--# derives ;
is
    Ctx : SHA2.Hash_Context;
begin
    Ctx := SHA2.Context_Init;
    SHA2.Context_Print (Ctx);
end Test_SHA2;
