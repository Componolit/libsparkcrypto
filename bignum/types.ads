with Interfaces;
--# inherit Interfaces;

-------------------------------------------------------------------------------
-- Primitive types and operations
-------------------------------------------------------------------------------
package Types is

   pragma Pure;

   -- 32-bit word
   subtype Word32 is Interfaces.Unsigned_32;

   -- 64-bit word
   subtype Word64 is Interfaces.Unsigned_64;

   -- Right shift 64-bit @Value@ by @Amount@
   function SHR (Value : Word64; Amount : Natural) return Word64;
   --# return Result => Result = Value / 2 ** Amount;
   pragma Inline (SHR);

   -- Left shift 64-bit @Value@ by @Amount@
   function SHL (Value : Word64; Amount : Natural) return Word64;
   --# return Result => Result = Value * 2 ** Amount;
   pragma Inline (SHL);

   -- Right shift 32-bit @Value@ by @Amount@
   function SHR32 (Value : Word32; Amount : Natural) return Word32;
   --# return Result => Result = Value / 2 ** Amount;
   pragma Inline (SHR32);

   -- Left shift 32-bit @Value@ by @Amount@
   function SHL32 (Value : Word32; Amount : Natural) return Word32;
   --# return Result => Result = Value * 2 ** Amount;
   pragma Inline (SHL32);

end Types;
