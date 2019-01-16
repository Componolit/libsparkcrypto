package body Util
is
   ---------
   -- B2S --
   ---------

   function B2S (Data : LSC.Types.Bytes) return String
   is
   begin
      return "Not implemented";
   end B2S;

   ---------
   -- S2B --
   ---------

   function S2B (Data : String) return LSC.Types.Bytes
   is
   begin
      return (1 => 0);
   end S2B;

end Util;
