with Interfaces;

package Types is

    subtype Word64 is Interfaces.Unsigned_64;

    function ROTR
        (Value  : Word64;
         Amount : Natural) return Word64 renames Interfaces.Rotate_Right;

    function SHR
        (Value  : Word64;
         Amount : Natural) return Word64 renames Interfaces.Shift_Right;

end Types;
