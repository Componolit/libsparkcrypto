separate (Main)
procedure AES_Tests is
   AES_Ctx : AES256.Context;
begin

   Test.Suite ("AES tests");

   --# accept Flow, 10, "Test not yet finished";
   --# accept Flow, 33, AES_Ctx, "Test not yet finished";
   AES_Ctx := AES256.Context_Init (Key => AES256.Key_Type'(16#60_3d_eb_10#,
                                                           16#15_ca_71_be#,
                                                           16#2b_73_ae_f0#,
                                                           16#85_7d_77_81#,
                                                           16#1f_35_2c_07#,
                                                           16#3b_61_08_d7#,
                                                           16#2d_98_10_a3#,
                                                           16#09_14_df_f4#));
end AES_Tests;
