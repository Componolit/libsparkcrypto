with SHA2, Types, IO;

--# inherit SHA2, Types, IO;

package Debug is

    procedure Print_Word64 (Item : in Types.Word64);
    --# derives null from Item;

    procedure Print_Hash (Hash : SHA2.Hash_Type);
    --# derives null from Hash;
        --
end Debug;
