package body LSC.Types
is
   ---------------
   -- Bytes_XOR --
   ---------------

   procedure Bytes_XOR
     (Left   : in     Types.Bytes;
      Right  : in     Types.Bytes;
      Result :    out Types.Bytes)
   is
   begin
      for I in Types.Natural_Index range 0 .. Left'Length - 1
       loop
         Result (Result'First + I) := Left (Left'First + I) xor Right (Right'First + I);
         pragma Loop_Invariant
            (for all Pos in Types.Natural_Index range 0 .. I =>
               (Result (Result'First + Pos) = (Left (Left'First + Pos) xor Right (Right'First + Pos))));
      end loop;
   end Bytes_XOR;

   pragma Annotate (GNATprove, False_Positive,
                    """Result"" might not be initialized",
                    "Initialized in complete loop in ""Bytes_XOR""");
end LSC.Types;
