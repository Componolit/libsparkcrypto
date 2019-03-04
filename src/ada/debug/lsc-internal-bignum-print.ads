with LSC.Internal.Bignum;

private package LSC.Internal.Bignum.Print
  with SPARK_Mode => Off
is
   pragma Pure;

   procedure Print_Big_Int
     (Item    : LSC.Internal.Bignum.Big_Int;
      Columns : Natural);

end LSC.Internal.Bignum.Print;
