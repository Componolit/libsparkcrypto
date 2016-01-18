theory LibSPARKcrypto
imports SPARK2014 Bignum
begin

abbreviation (input) dummy_conv where
  "dummy_conv x \<equiv> x"

(**** Lsc__types__word32 ****)

definition word32_in_range :: "32 word \<Rightarrow> bool" where
  "word32_in_range x = (BV32.ule (of_int 0) x \<and> BV32.ule x (of_int 4294967295))"

definition word32_in_range_int :: "int \<Rightarrow> bool" where
  "word32_in_range_int x = (0 \<le> x \<and> x \<le> 4294967295)"

lemma word32_range: "word32_in_range x"
  using uint_lt [of x]
  by (simp add: word32_in_range_def BV32.ule_def)

definition word32_to_int :: "32 word \<Rightarrow> int" ("\<lfloor>_\<rfloor>\<^sub>s") where
  "word32_to_int x = uint x"

lemma word32_range_int: "word32_in_range_int (word32_to_int x)"
  using uint_lt [of x]
  by (simp add: word32_in_range_int_def word32_to_int_def)

lemma word32_to_int_lower: "0 \<le> \<lfloor>x\<rfloor>\<^sub>s"
  using word32_range_int
  by (simp add: word32_in_range_int_def)

lemma word32_to_int_upper: "\<lfloor>x\<rfloor>\<^sub>s \<le> 4294967295"
  using word32_range_int
  by (simp add: word32_in_range_int_def)

lemma word32_to_int_upper': "\<lfloor>x\<rfloor>\<^sub>s < 4294967296"
  using word32_range_int
  by (simp add: word32_in_range_int_def zle_add1_eq_le [symmetric] del: zle_add1_eq_le)

lemma word32_uint_in_range: "BV32.uint_in_range \<lfloor>x\<rfloor>\<^sub>s"
  using word32_to_int_upper' [of x]
  by (simp add: BV32.uint_in_range_def word32_to_int_def)

why3_types
   Lsc__types__word32.word32 = word32

why3_consts
  Lsc__types__word32.to_rep = dummy_conv
  Lsc__types__word32.of_rep = dummy_conv

why3_defs
  Lsc__types__word32.in_range = word32_in_range_def and
  Lsc__types__word32.in_range_int = word32_in_range_int_def and
  Lsc__types__word32.to_int = word32_to_int_def

why3_thms
  Lsc__types__word32.inversion_axiom = refl and
  Lsc__types__word32.range_axiom = TrueI and
  Lsc__types__word32.range_int_axiom = word32_uint_in_range and
  Lsc__types__word32.coerce_axiom = refl

(**** Lsc__types__word64 ****)

definition word64_in_range :: "64 word \<Rightarrow> bool" where
  "word64_in_range x = (BV64.ule (of_int 0) x \<and> BV64.ule x (of_int 18446744073709551615))"

definition word64_in_range_int :: "int \<Rightarrow> bool" where
  "word64_in_range_int x = (0 \<le> x \<and> x \<le> 18446744073709551615)"

lemma word64_range: "word64_in_range x"
  using uint_lt [of x]
  by (simp add: word64_in_range_def BV64.ule_def)

definition word64_to_int :: "64 word \<Rightarrow> int" ("\<lfloor>_\<rfloor>\<^sub>l") where
  "word64_to_int x = uint x"

lemma word64_range_int: "word64_in_range_int (word64_to_int x)"
  using uint_lt [of x]
  by (simp add: word64_in_range_int_def word64_to_int_def)

lemma word64_to_int_lower: "0 \<le> \<lfloor>x\<rfloor>\<^sub>l"
  using word64_range_int
  by (simp add: word64_in_range_int_def)

lemma word64_to_int_upper: "\<lfloor>x\<rfloor>\<^sub>l \<le> 18446744073709551615"
  using word64_range_int
  by (simp add: word64_in_range_int_def)

lemma word64_to_int_upper': "\<lfloor>x\<rfloor>\<^sub>l < 18446744073709551616"
  using word64_range_int
  by (simp add: word64_in_range_int_def zle_add1_eq_le [symmetric] del: zle_add1_eq_le)

lemma word64_uint_in_range: "BV64.uint_in_range \<lfloor>x\<rfloor>\<^sub>l"
  using word64_to_int_upper' [of x]
  by (simp add: BV64.uint_in_range_def word64_to_int_def)

why3_types
   Lsc__types__word64.word64 = word64

why3_consts
  Lsc__types__word64.to_rep = dummy_conv
  Lsc__types__word64.of_rep = dummy_conv

why3_defs
  Lsc__types__word64.in_range = word64_in_range_def and
  Lsc__types__word64.in_range_int = word64_in_range_int_def and
  Lsc__types__word64.to_int = word64_to_int_def

why3_thms
  Lsc__types__word64.inversion_axiom = refl and
  Lsc__types__word64.range_axiom = TrueI and
  Lsc__types__word64.range_int_axiom = word64_uint_in_range and
  Lsc__types__word64.coerce_axiom = refl

(**** Array__Int__Lsc__types__word32 ****)

why3_consts
  Array__Int__Lsc__types__word32.bool_eq = array1_eq
  Array__Int__Lsc__types__word32.slide = slide

why3_thms
  Array__Int__Lsc__types__word32.T__ada_array___equal_def = array1_eq and
  Array__Int__Lsc__types__word32.slide_def = slide_def and
  Array__Int__Lsc__types__word32.slide_eq = slide_eq

(**** Lsc__bignum__big_int ****)

type_synonym bounds = "integer \<times> integer"

definition mk_bounds :: "int \<Rightarrow> int \<Rightarrow> bounds" ("\<langle>_\<dots>_\<rangle>") where
  "\<langle>f\<dots>l\<rangle> = (integer_of_int f, integer_of_int l)"

lemma mk_bounds_eqs:
  assumes "integer_in_range f" "integer_in_range l"
  shows "integer_to_int (fst \<langle>f\<dots>l\<rangle>) = f"
  and "integer_to_int (snd \<langle>f\<dots>l\<rangle>) = l"
  using assms
  by (simp_all add: mk_bounds_def integer_of_int_inverse)

lemma mk_bounds_fst: "fst \<langle>\<lfloor>f\<rfloor>\<^sub>\<int>\<dots>\<lfloor>l\<rfloor>\<^sub>\<int>\<rangle> = f"
  by (simp add: mk_bounds_def integer_to_int_inverse)

lemma mk_bounds_snd: "snd \<langle>\<lfloor>f\<rfloor>\<^sub>\<int>\<dots>\<lfloor>l\<rfloor>\<^sub>\<int>\<rangle> = l"
  by (simp add: mk_bounds_def integer_to_int_inverse)

lemma mk_bounds_expand:
  "\<lfloor>fst b\<rfloor>\<^sub>\<int> = \<lfloor>fst \<langle>\<lfloor>f\<rfloor>\<^sub>\<int>\<dots>\<lfloor>l\<rfloor>\<^sub>\<int>\<rangle>\<rfloor>\<^sub>\<int> \<Longrightarrow> \<lfloor>snd b\<rfloor>\<^sub>\<int> = \<lfloor>snd \<langle>\<lfloor>f\<rfloor>\<^sub>\<int>\<dots>\<lfloor>l\<rfloor>\<^sub>\<int>\<rangle>\<rfloor>\<^sub>\<int> \<Longrightarrow> b = \<langle>\<lfloor>f\<rfloor>\<^sub>\<int>\<dots>\<lfloor>l\<rfloor>\<^sub>\<int>\<rangle>"
  by (rule prod_eqI)
    (simp_all add: mk_bounds_fst mk_bounds_snd integer_to_int_inject)

datatype array = Array "int \<Rightarrow> word32" bounds

definition rt :: "array \<Rightarrow> bounds" where
  "rt v = (case v of Array a r \<Rightarrow> r)"

definition elts :: "array \<Rightarrow> int \<Rightarrow> word32" where
  "elts v = (case v of Array a r \<Rightarrow> a)"

lemma elts_Array [simp]: "elts (Array a r) = a"
  by (simp add: elts_def)

why3_types
  Lsc__bignum__big_int.t = bounds
  "Lsc__bignum__big_int.__t" = array

why3_consts
  Lsc__bignum__big_int.mk = mk_bounds
  Lsc__bignum__big_int.first = fst
  Lsc__bignum__big_int.last = snd

why3_defs
  Lsc__bignum__big_int.elts = elts_def and
  Lsc__bignum__big_int.rt = rt_def

why3_thms
  Lsc__bignum__big_int.mk_def = mk_bounds_eqs

(**** Temp___142 ****)

definition singleton0 :: "'a \<Rightarrow> 'a \<Rightarrow> int \<Rightarrow> 'a"
where
  "singleton0 x y = (\<lambda>i. y)(0 := x)"

lemma singleton0_eqs:
  "i = 0 \<longrightarrow> singleton0 x y i = x"
  "i \<noteq> 0 \<longrightarrow> singleton0 x y i = y"
  by (simp_all add: singleton0_def)

why3_consts
  Temp___142.temp___142 = singleton0

why3_thms
  Temp___142.def_axiom = singleton0_eqs

(**** Lsc__ec__one__axiom ****)

definition one :: "int \<Rightarrow> 32 word" where "one = singleton0 (of_int 1) (of_int 0)"

why3_consts
  Lsc__ec__one.one = one

why3_thms
  Lsc__ec__one__axiom.def_axiom = one_def

(**** Temp___lsc__ec_signature_142 ****)

why3_consts
  Temp___lsc__ec_signature_142.temp___lsc__ec_signature_142 = singleton0

why3_thms
  Temp___lsc__ec_signature_142.def_axiom = singleton0_eqs and
  Lsc__ec__one__axiom.one__def_axiom = one_def

(**** Lsc__ec_signature__signature_type ****)

datatype signature = ECDSA | ECGDSA

definition signature_in_range :: "int \<Rightarrow> bool" where
  "signature_in_range x = (0 \<le> x \<and> x \<le> 1)"

primrec signature_to_int :: "signature \<Rightarrow> int" where
  "signature_to_int ECDSA = 0"
| "signature_to_int ECGDSA = 1"

definition signature_of_int :: "int \<Rightarrow> signature" where
  "signature_of_int i = (if i = 0 then ECDSA else ECGDSA)"

lemma signature_inversion: "signature_of_int (signature_to_int x) = x"
  by (cases x) (simp_all add: signature_of_int_def)

lemma signature_to_int: "signature_in_range (signature_to_int x)"
  by (cases x) (simp_all add: signature_in_range_def)

lemma signature_coerce:
  "signature_in_range x \<Longrightarrow> signature_to_int (signature_of_int x) = x"
  by (simp add: signature_of_int_def signature_in_range_def)

why3_types
   Lsc__ec_signature__signature_type.signature_type = signature

why3_consts
  Lsc__ec_signature__signature_type.to_rep = signature_to_int
  Lsc__ec_signature__signature_type.of_rep = signature_of_int

why3_defs
  Lsc__ec_signature__signature_type.in_range = signature_in_range_def

why3_thms
  Lsc__ec_signature__signature_type.inversion_axiom = signature_inversion and
  Lsc__ec_signature__signature_type.range_axiom = signature_to_int and
  Lsc__ec_signature__signature_type.coerce_axiom = signature_coerce

(**** Mathematical integers ****)

(**** Lsc__math_int__math_int ****)

datatype math_int' = mk_math_int' int

definition dest_math_int' :: "math_int' \<Rightarrow> int" where
  "dest_math_int' v = (case v of mk_math_int' x \<Rightarrow> x)"

datatype math_int = mk_math_int math_int'

definition dest_math_int :: "math_int \<Rightarrow> math_int'" where
  "dest_math_int v = (case v of mk_math_int x \<Rightarrow> x)"

definition int_of_math_int :: "math_int \<Rightarrow> int" where
  "int_of_math_int = dest_math_int' o dest_math_int"

definition math_int_of_int :: "int \<Rightarrow> math_int" where
  "math_int_of_int = mk_math_int o mk_math_int'"

lemma int_of_math_int_inv [simp]: "math_int_of_int (int_of_math_int x) = x"
  by (simp add: math_int_of_int_def int_of_math_int_def
    dest_math_int_def dest_math_int'_def
    split add: math_int.split math_int'.split)

lemma math_int_of_int_inv [simp]: "int_of_math_int (math_int_of_int x) = x"
  by (simp add: math_int_of_int_def int_of_math_int_def
    dest_math_int_def dest_math_int'_def)

lemma math_int_eq: "(x = y) = (int_of_math_int x = int_of_math_int y)"
  by (simp add: int_of_math_int_def
    dest_math_int_def dest_math_int'_def
    split add: math_int.split math_int'.split)

definition math_int_object_size :: "math_int \<Rightarrow> int" where
  "math_int_object_size x = 0"

lemma math_int_object_size: "0 \<le> math_int_object_size a"
  by (simp add: math_int_object_size_def)

definition math_int_from_word :: "'a::len0 word \<Rightarrow> math_int" where
  "math_int_from_word i \<equiv> math_int_of_int (uint i)"

instantiation math_int :: comm_ring_1
begin

definition "0 = math_int_of_int 0"

definition "1 = math_int_of_int 1"

definition "- i = math_int_of_int (- int_of_math_int i)"

definition "i + j = math_int_of_int (int_of_math_int i + int_of_math_int j)"

definition "i - j = math_int_of_int (int_of_math_int i - int_of_math_int j)"

definition "i * j = math_int_of_int (int_of_math_int i * int_of_math_int j)"

instance
  by intro_classes (simp_all add: times_math_int_def plus_math_int_def minus_math_int_def
    uminus_math_int_def zero_math_int_def one_math_int_def ring_distribs math_int_eq)

end

instantiation math_int :: Divides.div
begin

definition "a div b = math_int_of_int (int_of_math_int a div int_of_math_int b)"

definition "a mod b = math_int_of_int (int_of_math_int a mod int_of_math_int b)"

instance ..

end

instantiation math_int :: linorder
begin

definition "x < y = (int_of_math_int x < int_of_math_int y)"

definition "x \<le> y = (int_of_math_int x \<le> int_of_math_int y)"

instance
  by intro_classes
    (simp_all add: less_math_int_def less_eq_math_int_def math_int_eq
       less_le_not_le linorder_linear)

end

lemma math_int_conv':
  "int_of_math_int 0 = 0"
  "int_of_math_int 1 = 1"
  "int_of_math_int (- i) = - int_of_math_int i"
  "int_of_math_int (i + j) = int_of_math_int i + int_of_math_int j"
  "int_of_math_int (i - j) = int_of_math_int i - int_of_math_int j"
  "int_of_math_int (i * j) = int_of_math_int i * int_of_math_int j"
  "int_of_math_int (i div j) = int_of_math_int i div int_of_math_int j"
  "int_of_math_int (i mod j) = int_of_math_int i mod int_of_math_int j"
  by (simp_all add: zero_math_int_def one_math_int_def uminus_math_int_def
    plus_math_int_def minus_math_int_def times_math_int_def
    div_math_int_def mod_math_int_def)

lemma math_int_power: "int_of_math_int (x ^ n) = int_of_math_int x ^ n"
  by (induct n) (simp_all add: math_int_conv')

lemma math_int_numeral: "int_of_math_int (numeral x) = numeral x"
  by (induct x) (simp_all only: numeral.simps math_int_conv')

lemmas math_int_conv [simp] =
  math_int_eq less_math_int_def less_eq_math_int_def
  math_int_conv' math_int_power math_int_numeral

lemma int_of_math_int_word [simp]: "int_of_math_int (math_int_from_word x) = uint x"
  by (simp add: math_int_from_word_def)

lemma int_of_math_int_num_of_bool [simp]:
  "int_of_math_int (num_of_bool b) = num_of_bool b"
  by (cases b) simp_all

abbreviation (input) power_math_int :: "('a::power) \<Rightarrow> math_int \<Rightarrow> 'a" where
  "power_math_int i j \<equiv> power_int i (int_of_math_int j)"

why3_types
  "_gnatprove_standard_th.Main_Main.__private" = int
  "Lsc__math_int__math_int.__split_fields" = math_int'
  Lsc__math_int__math_int.math_int = math_int

why3_defs
  "Lsc__math_int__math_int.rec__main__" = dest_math_int'_def and
  "Lsc__math_int__math_int.__split_fields" = dest_math_int_def

why3_thms
  Lsc__math_int__math_int.value__size_axiom = order_refl and
  Lsc__math_int__math_int.object__size_axiom = math_int_object_size

why3_consts
  Lsc__math_int__math_int.user_eq = HOL.eq
  Lsc__math_int__math_int.value__size = zero_class.zero
  Lsc__math_int__math_int.object__size = math_int_object_size
  Lsc__math_int__Oeq.oeq = HOL.eq
  Lsc__math_int__Olt.olt = less
  Lsc__math_int__Ole.ole = less_eq
  Lsc__math_int__Ogt.ogt = greater
  Lsc__math_int__Oge.oge = greater_eq
  Lsc__math_int__Oadd.oadd = plus
  Lsc__math_int__Osubtract.osubtract = minus
  Lsc__math_int__Omultiply.omultiply = times
  Lsc__math_int__Odivide.odivide = div
  Lsc__math_int__Omod.omod = mod
  Lsc__math_int__Oexpon.oexpon = power_int
  Lsc__math_int__Oexpon__2.oexpon__2 = power_math_int
  Lsc__math_int__from_word32.from_word32 = math_int_from_word
  Lsc__math_int__from_word64.from_word64 = math_int_from_word
  Lsc__math_int__from_integer.from_integer = math_int_of_int

(**** Lsc__bignum__num_of_big_int ****)

abbreviation num_of_big_int' :: "array \<Rightarrow> int \<Rightarrow> int \<Rightarrow> math_int" where
  "num_of_big_int' a i j \<equiv> math_int_of_int (num_of_big_int (word32_to_int o elts a) i j)"

why3_consts
  Lsc__bignum__num_of_big_int.num_of_big_int = num_of_big_int'

(**** Lsc__bignum__num_of_boolean ****)

why3_consts
  Lsc__bignum__num_of_boolean.num_of_boolean = num_of_bool

(**** Lsc__bignum__inverse ****)

abbreviation (input) math_int_inv :: "math_int \<Rightarrow> math_int \<Rightarrow> math_int" where
  "math_int_inv m x \<equiv> math_int_of_int (minv (int_of_math_int m) (int_of_math_int x))"

why3_consts
  Lsc__bignum__inverse.inverse = math_int_inv

(**** Lsc__bignum__gcd ****)

abbreviation (input) gcd_word :: "'a::len word \<Rightarrow> 'a word \<Rightarrow> 'a word" where
  "gcd_word x y \<equiv> of_int (gcd (uint x) (uint y))"

why3_consts
  Lsc__bignum__gcd.gcd = gcd_word

(**** Lsc__bignum__base(__axiom) ****)

definition base :: "unit \<Rightarrow> math_int" where
  "base x = math_int_from_word (of_int 2 :: 32 word) ^ nat 32"

lemma base_eq: "base x = Base"
  using one_add_one [where 'a=math_int, unfolded plus_math_int_def one_math_int_def]
  by (simp add: base_def math_int_from_word_def del: math_int_conv)

lemma int_of_math_int_Base [simp]: "int_of_math_int Base = Base"
  by (simp add: base_eq [of "()", symmetric] base_def)

why3_consts
  Lsc__bignum__base.base = base

why3_thms
  Lsc__bignum__base__axiom.base__def_axiom = base_def

end
