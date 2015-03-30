theory LibSPARKcrypto
imports SPARK2014 Bignum
begin

(**** Lsc__types__word32 ****)

definition word32_in_range :: "int \<Rightarrow> bool" where
  "word32_in_range x = (0 \<le> x \<and> x \<le> 4294967295)"

typedef word32 = "{x::int. word32_in_range x}"
  morphisms word32_to_int word32_of_int'
  by (auto simp add: word32_in_range_def)

definition word32_of_int :: "int \<Rightarrow> word32" where
  "word32_of_int x = word32_of_int' (x emod 4294967296)"

notation
  word32_to_int ("\<lfloor>_\<rfloor>\<^bsub>w32\<^esub>") and
  word32_of_int ("\<lceil>_\<rceil>\<^bsub>w32\<^esub>")

lemma word32_to_int_in_range: "word32_in_range \<lfloor>x\<rfloor>\<^bsub>w32\<^esub>"
  using word32_to_int
  by simp

lemma word32_to_int_lower: "0 \<le> \<lfloor>x\<rfloor>\<^bsub>w32\<^esub>"
  using word32_to_int
  by (simp add: word32_in_range_def)

lemma word32_to_int_upper: "\<lfloor>x\<rfloor>\<^bsub>w32\<^esub> \<le> 4294967295"
  using word32_to_int
  by (simp add: word32_in_range_def)

lemma word32_to_int_upper': "\<lfloor>x\<rfloor>\<^bsub>w32\<^esub> < 4294967296"
  using word32_to_int
  by (simp add: word32_in_range_def zle_add1_eq_le [symmetric] del: zle_add1_eq_le)

lemma word32_coerce: "\<lfloor>\<lceil>x\<rceil>\<^bsub>w32\<^esub>\<rfloor>\<^bsub>w32\<^esub> = x emod 4294967296"
  by (simp add: word32_of_int_def word32_of_int'_inverse
    word32_in_range_def emod_def)

lemma word32_inversion: "\<lceil>\<lfloor>x\<rfloor>\<^bsub>w32\<^esub>\<rceil>\<^bsub>w32\<^esub> = x"
  by (simp add: word32_of_int_def word32_to_int_inverse
    emod_def mod_pos_pos_trivial word32_to_int_lower word32_to_int_upper')

instantiation word32 :: linorder
begin

definition less_eq_word32 where
  "i \<le> j = (\<lfloor>i\<rfloor>\<^bsub>w32\<^esub> \<le> \<lfloor>j\<rfloor>\<^bsub>w32\<^esub>)"

definition less_word32 where
  "i < j = (\<lfloor>i\<rfloor>\<^bsub>w32\<^esub> < \<lfloor>j\<rfloor>\<^bsub>w32\<^esub>)"

instance
  by default (simp_all add: less_eq_word32_def less_word32_def
    less_le_not_le linorder_linear word32_to_int_inject)

end

why3_types
   Lsc__types__word32.word32 = word32

why3_consts
  Lsc__types__word32.to_int = word32_to_int
  Lsc__types__word32.of_int = word32_of_int

why3_defs
  Lsc__types__word32.in_range = word32_in_range_def

why3_thms
  Lsc__types__word32.inversion_axiom = word32_inversion and
  Lsc__types__word32.range_axiom = word32_to_int [simplified] and
  Lsc__types__word32.coerce_axiom = word32_coerce

(**** Lsc__types__word64 ****)

definition word64_in_range :: "int \<Rightarrow> bool" where
  "word64_in_range x = (0 \<le> x \<and> x \<le> 18446744073709551615)"

typedef word64 = "{x::int. word64_in_range x}"
  morphisms word64_to_int word64_of_int'
  by (auto simp add: word64_in_range_def)

definition word64_of_int :: "int \<Rightarrow> word64" where
  "word64_of_int x = word64_of_int' (x emod 18446744073709551616)"

notation
  word64_to_int ("\<lfloor>_\<rfloor>\<^bsub>w64\<^esub>") and
  word64_of_int ("\<lceil>_\<rceil>\<^bsub>w64\<^esub>")

lemma word64_to_int_in_range: "word64_in_range \<lfloor>x\<rfloor>\<^bsub>w64\<^esub>"
  using word64_to_int
  by simp

lemma word64_to_int_lower: "0 \<le> \<lfloor>x\<rfloor>\<^bsub>w64\<^esub>"
  using word64_to_int
  by (simp add: word64_in_range_def)

lemma word64_to_int_upper: "\<lfloor>x\<rfloor>\<^bsub>w64\<^esub> \<le> 18446744073709551615"
  using word64_to_int
  by (simp add: word64_in_range_def)

lemma word64_to_int_upper': "\<lfloor>x\<rfloor>\<^bsub>w64\<^esub> < 18446744073709551616"
  using word64_to_int
  by (simp add: word64_in_range_def zle_add1_eq_le [symmetric] del: zle_add1_eq_le)

lemma word64_coerce: "\<lfloor>\<lceil>x\<rceil>\<^bsub>w64\<^esub>\<rfloor>\<^bsub>w64\<^esub> = x emod 18446744073709551616"
  by (simp add: word64_of_int_def word64_of_int'_inverse
    word64_in_range_def emod_def)

lemma word64_inversion: "\<lceil>\<lfloor>x\<rfloor>\<^bsub>w64\<^esub>\<rceil>\<^bsub>w64\<^esub> = x"
  by (simp add: word64_of_int_def word64_to_int_inverse
    emod_def mod_pos_pos_trivial word64_to_int_lower word64_to_int_upper')

instantiation word64 :: linorder
begin

definition less_eq_word64 where
  "i \<le> j = (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> \<le> \<lfloor>j\<rfloor>\<^bsub>w64\<^esub>)"

definition less_word64 where
  "i < j = (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> < \<lfloor>j\<rfloor>\<^bsub>w64\<^esub>)"

instance
  by default (simp_all add: less_eq_word64_def less_word64_def
    less_le_not_le linorder_linear word64_to_int_inject)

end

why3_types
   Lsc__types__word64.word64 = word64

why3_consts
  Lsc__types__word64.to_int = word64_to_int
  Lsc__types__word64.of_int = word64_of_int

why3_defs
  Lsc__types__word64.in_range = word64_in_range_def

why3_thms
  Lsc__types__word64.inversion_axiom = word64_inversion and
  Lsc__types__word64.range_axiom = word64_to_int [simplified] and
  Lsc__types__word64.coerce_axiom = word64_coerce

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

(**** Temp___lsc__ec_signature_1 ****)

definition singleton0 :: "word32 \<Rightarrow> word32 \<Rightarrow> int \<Rightarrow> word32"
where
  "singleton0 x y = (\<lambda>i. y)(0 := x)"

lemma singleton0_eqs:
  "i = 0 \<longrightarrow> singleton0 x y i = x"
  "i \<noteq> 0 \<longrightarrow> singleton0 x y i = y"
  by (simp_all add: singleton0_def)

(**** Lsc__ec__one__axiom ****)

definition "one = singleton0 \<lceil>1\<rceil>\<^bsub>w32\<^esub> \<lceil>0\<rceil>\<^bsub>w32\<^esub>"

why3_consts
  Temp___lsc__ec_signature_1.temp___lsc__ec_signature_1 = singleton0
  Lsc__ec__one.one = one

why3_thms
  Temp___lsc__ec_signature_1.def_axiom = singleton0_eqs and
  Lsc__ec__one__axiom.def_axiom = one_def

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
  Lsc__ec_signature__signature_type.to_int = signature_to_int
  Lsc__ec_signature__signature_type.of_int = signature_of_int

why3_defs
  Lsc__ec_signature__signature_type.in_range = signature_in_range_def

why3_thms
  Lsc__ec_signature__signature_type.inversion_axiom = signature_inversion and
  Lsc__ec_signature__signature_type.range_axiom = signature_to_int and
  Lsc__ec_signature__signature_type.coerce_axiom = signature_coerce

(**** Mathematical integers ****)

abbreviation (input) dummy_conv :: "int \<Rightarrow> int" where
  "dummy_conv i \<equiv> i"

abbreviation (input) power_int :: "int \<Rightarrow> int \<Rightarrow> int" where
  "power_int i j \<equiv> i ^ nat j"

why3_types
  "_gnatprove_standard_th.Main_Main.__private" = int

why3_consts
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
  Lsc__math_int__Oexpon__2.oexpon__2 = power_int
  Lsc__math_int__from_word32.from_word32 = dummy_conv
  Lsc__math_int__from_word64.from_word64 = dummy_conv
  Lsc__math_int__from_integer.from_integer = dummy_conv

(**** Lsc__bignum__num_of_big_int ****)

abbreviation num_of_big_int' :: "array \<Rightarrow> int \<Rightarrow> int \<Rightarrow> int" where
  "num_of_big_int' a \<equiv> num_of_big_int (word32_to_int o elts a)"

why3_consts
  Lsc__bignum__num_of_big_int.num_of_big_int = num_of_big_int'

(**** Lsc__bignum__num_of_boolean ****)

why3_consts
  Lsc__bignum__num_of_boolean.num_of_boolean = num_of_bool

(**** Lsc__bignum__inverse ****)

why3_consts
  Lsc__bignum__inverse.inverse = minv

(**** Lsc__bignum__gcd ****)

abbreviation (input) gcd_w32 :: "int \<Rightarrow> int \<Rightarrow> word32" where
  "gcd_w32 x y \<equiv> \<lceil>gcd x y\<rceil>\<^bsub>w32\<^esub>"

why3_consts
  Lsc__bignum__gcd.gcd = gcd_w32

(**** Lsc__bignum__base(__axiom) ****)

definition base :: "unit \<Rightarrow> int" where
  "base x = 2 ^ nat 32"

lemma base_eq: "base x = Base"
  by (simp add: base_def)

why3_consts
  Lsc__bignum__base.base = base

why3_thms
  Lsc__bignum__base__axiom.base__def_axiom = base_def

end