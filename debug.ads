with Bignum;

package Debug
is
   procedure Message (Msg : String);

   procedure Put_Big_Int
     (Item : Bignum.Big_Int;
      Columns : Natural);
end Debug;
