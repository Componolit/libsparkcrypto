with LSC.Bignum;

private package LSC.Bignum.Print
  with SPARK_Mode => Off
is
   pragma Preelaborate;

   procedure Print_Big_Int
     (Item    : LSC.Bignum.Big_Int;
      Columns : Natural);

end LSC.Bignum.Print;
