--# inherit AES256;

private package AES256.Debug is

   procedure Print_Schedule (S : AES256.Schedule_Type);
   --# derives null from S;

end AES256.Debug;
