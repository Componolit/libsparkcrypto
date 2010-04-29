private package SHA2.Debug is

    procedure Put_Line (T : String);

    procedure Put_T (T : SHA2.Schedule_Index);
    procedure Put_State (S : SHA2.State_Type);
    procedure Put_Hash (H : SHA2.Hash_Type);
    procedure Put_Schedule (S : SHA2.Schedule_Type);

end SHA2.Debug;
