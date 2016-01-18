theory SPARK2014
imports Why3
begin

(**** _gnatprove_standard.Boolean ****)

definition bool_of_int :: "int \<Rightarrow> bool" where
  "bool_of_int i = (if i = 0 then False else True)"

(* avoid shadowing of standard of_int function *)

why3_defs
  "_gnatprove_standard.Boolean.of_int" = bool_of_int_def


(**** _gnatprove_standard_th.Integer ****)

lemma bool_eq: "((x = y) = True) = (x = y)" by simp

definition bool_ne :: "int \<Rightarrow> int \<Rightarrow> bool" where
  "bool_ne x y = (x \<noteq> y)"

lemma bool_ne: "(bool_ne x y = True) = (x \<noteq> y)"
  by (simp add: bool_ne_def)

lemma bool_lt: "((x < y) = True) = (x < y)" by simp

lemma bool_le: "((x \<le> y) = True) = (x \<le> y)" by simp

definition bool_gt :: "int \<Rightarrow> int \<Rightarrow> bool" where
  "bool_gt x y = (x > y)"

lemma bool_gt: "(bool_gt x y = True) = (y < x)"
  by (simp add: bool_gt_def)

definition bool_ge :: "int \<Rightarrow> int \<Rightarrow> bool" where
  "bool_ge x y = (x \<ge> y)"

lemma bool_ge: "(bool_ge x y = True) = (y \<le> x)"
  by (simp add: bool_ge_def)

why3_consts
  "_gnatprove_standard_th.Integer.bool_eq" = HOL.eq
  "_gnatprove_standard_th.Integer.bool_ne" = bool_ne
  "_gnatprove_standard_th.Integer.bool_lt" = Orderings.ord_class.less
  "_gnatprove_standard_th.Integer.bool_le" = Orderings.ord_class.less_eq
  "_gnatprove_standard_th.Integer.bool_gt" = bool_gt
  "_gnatprove_standard_th.Integer.bool_ge" = bool_ge

why3_thms
  "_gnatprove_standard_th.Integer.bool_eq_axiom" = bool_eq and
  "_gnatprove_standard_th.Integer.bool_ne_axiom" = bool_ne and
  "_gnatprove_standard_th.Integer.bool_lt_axiom" = bool_lt and
  "_gnatprove_standard_th.Integer.bool_int__le_axiom" = bool_le and
  "_gnatprove_standard_th.Integer.bool_gt_axiom" = bool_gt and
  "_gnatprove_standard_th.Integer.bool_ge_axiom" = bool_ge


(**** Standard__integer ****)

definition integer_in_range :: "int \<Rightarrow> bool" where
  "integer_in_range x = (- 2147483648 \<le> x \<and> x \<le> 2147483647)"

typedef integer = "{x::int. integer_in_range x}"
  morphisms integer_to_int integer_of_int
  by (auto simp add: integer_in_range_def)

notation
  integer_to_int ("\<lfloor>_\<rfloor>\<^sub>\<int>") and
  integer_of_int ("\<lceil>_\<rceil>\<^sub>\<int>")

lemma integer_to_int_in_range: "integer_in_range \<lfloor>x\<rfloor>\<^sub>\<int>"
  using integer_to_int
  by simp

lemma integer_to_int_lower: "- 2147483648 \<le> \<lfloor>x\<rfloor>\<^sub>\<int>"
  using integer_to_int
  by (simp add: integer_in_range_def)

lemma integer_to_int_upper: "\<lfloor>x\<rfloor>\<^sub>\<int> \<le> 2147483647"
  using integer_to_int
  by (simp add: integer_in_range_def)

instantiation integer :: linorder
begin

definition less_eq_integer where
  "i \<le> j = (\<lfloor>i\<rfloor>\<^sub>\<int> \<le> \<lfloor>j\<rfloor>\<^sub>\<int>)"

definition less_integer where
  "i < j = (\<lfloor>i\<rfloor>\<^sub>\<int> < \<lfloor>j\<rfloor>\<^sub>\<int>)"

instance
  by default (simp_all add: less_eq_integer_def less_integer_def
    less_le_not_le linorder_linear integer_to_int_inject)

end

why3_types
  Standard__integer.integer = integer

why3_consts
  Standard__integer.to_rep = integer_to_int
  Standard__integer.of_rep = integer_of_int

why3_defs
  Standard__integer.in_range = integer_in_range_def

why3_thms
  Standard__integer.inversion_axiom = integer_to_int_inverse and
  Standard__integer.range_axiom = integer_to_int [simplified] and
  Standard__integer.coerce_axiom = integer_of_int_inverse [simplified]


(**** Standard__natural ****)

definition natural_in_range :: "int \<Rightarrow> bool" where
  "natural_in_range x = (0 \<le> x \<and> x \<le> 2147483647)"

typedef natural = "{x::int. natural_in_range x}"
  morphisms natural_to_int natural_of_int
  by (auto simp add: natural_in_range_def)

notation
  natural_to_int ("\<lfloor>_\<rfloor>\<^sub>\<nat>") and
  natural_of_int ("\<lceil>_\<rceil>\<^sub>\<nat>")

lemma natural_to_int_in_range: "natural_in_range \<lfloor>x\<rfloor>\<^sub>\<nat>"
  using natural_to_int
  by simp

lemma natural_to_int_lower: "0 \<le> \<lfloor>x\<rfloor>\<^sub>\<nat>"
  using natural_to_int
  by (simp add: natural_in_range_def)

lemma natural_to_int_upper: "\<lfloor>x\<rfloor>\<^sub>\<nat> \<le> 2147483647"
  using natural_to_int
  by (simp add: natural_in_range_def)

instantiation natural :: linorder
begin

definition less_eq_natural where
  "i \<le> j = (\<lfloor>i\<rfloor>\<^sub>\<nat> \<le> \<lfloor>j\<rfloor>\<^sub>\<nat>)"

definition less_natural where
  "i < j = (\<lfloor>i\<rfloor>\<^sub>\<nat> < \<lfloor>j\<rfloor>\<^sub>\<nat>)"

instance
  by default (simp_all add: less_eq_natural_def less_natural_def
    less_le_not_le linorder_linear natural_to_int_inject)

end

why3_types
  Standard__natural.natural = natural

why3_consts
  Standard__natural.to_rep = natural_to_int
  Standard__natural.of_rep = natural_of_int

why3_defs
  Standard__natural.in_range = natural_in_range_def

why3_thms
  Standard__natural.inversion_axiom = natural_to_int_inverse and
  Standard__natural.range_axiom = natural_to_int [simplified] and
  Standard__natural.coerce_axiom = natural_of_int_inverse [simplified]


(**** Interfaces__unsigned_64 ****)

definition unsigned_64_in_range :: "64 word \<Rightarrow> bool" where
  "unsigned_64_in_range x =
     (BV64.ule (of_int 0) x \<and>
      BV64.ule x (of_int 18446744073709551615))"

definition unsigned_64_in_range_int :: "int \<Rightarrow> bool" where
  "unsigned_64_in_range_int x = (0 \<le> x \<and> x \<le> 18446744073709551615)"

definition unsigned_64_bool_eq :: "64 word \<Rightarrow> 64 word \<Rightarrow> bool" where
  "unsigned_64_bool_eq x y = (if x = y then True else False)"

definition unsigned_64_to_rep :: "64 word \<Rightarrow> 64 word" where
  "unsigned_64_to_rep = id"

definition unsigned_64_of_rep :: "64 word \<Rightarrow> 64 word" where
  "unsigned_64_of_rep = id"

lemma unsigned_64_inversion:
  "unsigned_64_of_rep (unsigned_64_to_rep x) = x"
  by (simp add: unsigned_64_of_rep_def unsigned_64_to_rep_def)

lemma unsigned_64_range: "unsigned_64_in_range (unsigned_64_to_rep x)"
  using uint_lt [of x]
  by (simp add: unsigned_64_in_range_def unsigned_64_to_rep_def BV64.ule_def)

definition unsigned_64_to_int :: "64 word \<Rightarrow> int" where
  "unsigned_64_to_int x = uint (unsigned_64_to_rep x)"

lemma unsigned_64_range_int:
  "unsigned_64_in_range_int (unsigned_64_to_int x)"
  using uint_lt [of x]
  by (simp add: unsigned_64_in_range_int_def unsigned_64_to_int_def
    unsigned_64_to_rep_def)

lemma unsigned_64_coerce:
  "unsigned_64_to_rep (unsigned_64_of_rep x) = x"
  by (simp add: unsigned_64_of_rep_def unsigned_64_to_rep_def)

lemma unsigned_64_uint_in_range: "BV64.uint_in_range (unsigned_64_to_int x)"
  using unsigned_64_range_int [of x]
  by (simp add: BV64.uint_in_range_def unsigned_64_to_int_def unsigned_64_in_range_int_def)

why3_types
  Interfaces__unsigned_64.unsigned_64 = word64

why3_consts
  Interfaces__unsigned_64.of_rep = unsigned_64_of_rep
  Interfaces__unsigned_64.to_rep = unsigned_64_to_rep

why3_defs
  Interfaces__unsigned_64.in_range = unsigned_64_in_range_def and
  Interfaces__unsigned_64.in_range_int = unsigned_64_in_range_int_def and
  Interfaces__unsigned_64.bool_eq = unsigned_64_bool_eq_def and
  Interfaces__unsigned_64.to_int = unsigned_64_to_int_def

why3_thms
  Interfaces__unsigned_64.inversion_axiom = unsigned_64_inversion and
  Interfaces__unsigned_64.range_axiom = TrueI and
  Interfaces__unsigned_64.range_int_axiom = unsigned_64_uint_in_range and
  Interfaces__unsigned_64.coerce_axiom = unsigned_64_coerce


(**** _gnatprove_standard.BV32 ****)

abbreviation (input) power_int :: "('a::power) \<Rightarrow> int \<Rightarrow> 'a" where
  "power_int i j \<equiv> i ^ nat j"

lemma Power_0: "power_int x 0 = of_int 1"
  by simp

lemma Power_1: "power_int (x::'a::monoid_mult) 1 = x"
  by simp

lemma Power_s:
  "0 \<le> n \<Longrightarrow> power_int x (n + 1) = x * power_int x n"
  by (simp add: nat_add_distrib)

lemma Power_s_alt:
  "0 < n \<Longrightarrow> power_int (x::'a::monoid_mult) n = x * power_int x (n - 1)"
  using power_add [of x 1, symmetric]
  by (simp add: nat_diff_distrib del: power.simps)

lemma Power_sum:
  "0 \<le> n \<Longrightarrow> 0 \<le> m \<Longrightarrow>
   power_int (x::'a::monoid_mult) (n + m) = power_int x n * power_int x m"
  by (simp add: nat_add_distrib power_add)

lemma Power_mult:
  "0 \<le> n \<Longrightarrow> 0 \<le> m \<Longrightarrow>
   power_int (x::'a::monoid_mult) (n * m) = power_int (power_int x n) m"
  by (simp add: nat_mult_distrib power_mult)

lemma Power_mult2:
  "0 \<le> n \<Longrightarrow> power_int ((x::'a::comm_monoid_mult) * y) n = power_int x n * power_int y n"
  by (simp add: power_mult_distrib)

definition bv32_min :: "32 word \<Rightarrow> 32 word \<Rightarrow> 32 word" where
  "bv32_min x y = (if BV32.ule x y then x else y)"

definition bv32_max :: "32 word \<Rightarrow> 32 word \<Rightarrow> 32 word" where
  "bv32_max x y = (if BV32.ule x y then y else x)"

lemma bv32_min_to_uint: "uint (bv32_min x y) = min (uint x) (uint y)"
  by (simp add: bv32_min_def BV32.ule_def min_absorb1 min_absorb2)

lemma bv32_max_to_uint: "uint (bv32_max x y) = max (uint x) (uint y)"
  by (simp add: bv32_max_def BV32.ule_def max_absorb1 max_absorb2)

why3_consts
  "_gnatprove_standard.BV32.power" = power_int

why3_defs
  "_gnatprove_standard.BV32.bv_min" = bv32_min_def and
  "_gnatprove_standard.BV32.bv_max" = bv32_max_def

why3_thms
  "_gnatprove_standard.BV32.Power_0" = Power_0 and
  "_gnatprove_standard.BV32.Power_1" = Power_1 and
  "_gnatprove_standard.BV32.Power_s" = Power_s and
  "_gnatprove_standard.BV32.Power_s_alt" = Power_s_alt and
  "_gnatprove_standard.BV32.Power_sum" = Power_sum and
  "_gnatprove_standard.BV32.Power_mult" = Power_mult and
  "_gnatprove_standard.BV32.Power_mult2" = Power_mult2 and
  "_gnatprove_standard.BV32.bv_min_to_uint" = bv32_min_to_uint and
  "_gnatprove_standard.BV32.bv_max_to_uint" = bv32_max_to_uint


(**** _gnatprove_standard.BV64 ****)

definition bv64_min :: "64 word \<Rightarrow> 64 word \<Rightarrow> 64 word" where
  "bv64_min x y = (if BV64.ule x y then x else y)"

definition bv64_max :: "64 word \<Rightarrow> 64 word \<Rightarrow> 64 word" where
  "bv64_max x y = (if BV64.ule x y then y else x)"

lemma bv64_min_to_uint: "uint (bv64_min x y) = min (uint x) (uint y)"
  by (simp add: bv64_min_def BV64.ule_def min_absorb1 min_absorb2)

lemma bv64_max_to_uint: "uint (bv64_max x y) = max (uint x) (uint y)"
  by (simp add: bv64_max_def BV64.ule_def max_absorb1 max_absorb2)

why3_consts
  "_gnatprove_standard.BV64.power" = power_int

why3_defs
  "_gnatprove_standard.BV64.bv_min" = bv64_min_def and
  "_gnatprove_standard.BV64.bv_max" = bv64_max_def

why3_thms
  "_gnatprove_standard.BV64.Power_0" = Power_0 and
  "_gnatprove_standard.BV64.Power_1" = Power_1 and
  "_gnatprove_standard.BV64.Power_s" = Power_s and
  "_gnatprove_standard.BV64.Power_s_alt" = Power_s_alt and
  "_gnatprove_standard.BV64.Power_sum" = Power_sum and
  "_gnatprove_standard.BV64.Power_mult" = Power_mult and
  "_gnatprove_standard.BV64.Power_mult2" = Power_mult2 and
  "_gnatprove_standard.BV64.bv_min_to_uint" = bv64_min_to_uint and
  "_gnatprove_standard.BV64.bv_max_to_uint" = bv64_max_to_uint


(**** Arrays ****)

definition array1_eq :: "(int \<Rightarrow> 'a) \<Rightarrow> int \<Rightarrow> int \<Rightarrow> (int \<Rightarrow> 'a) \<Rightarrow> int \<Rightarrow> int \<Rightarrow> bool"
where
  "array1_eq a af al b bf bl =
     ((af \<le> al \<and> al - af = bl - bf \<or> \<not> af \<le> al \<and> bl < bf) \<and>
      (\<forall>i. af \<le> i \<and> i \<le> al \<longrightarrow> a i = b (bf - af + i)))"

lemma array1_eq:
  "(af \<le> al \<and> al - af + 1 = bl - bf + 1 \<or> \<not> af \<le> al \<and> bl < bf) \<and>
   (\<forall>i. af \<le> i \<and> i \<le> al \<longrightarrow> a i = b (bf - af + i)) \<longrightarrow>
   array1_eq a af al b bf bl = True"
  "array1_eq a af al b bf bl = True \<longrightarrow>
   ((af \<le> al \<longrightarrow> al - af + 1 = bl - bf + 1) \<and> (\<not> af \<le> al \<longrightarrow> bl < bf)) \<and>
   (\<forall>i. af \<le> i \<and> i \<le> al \<longrightarrow> a i = b (bf - af + i))"
  by (auto simp add: array1_eq_def)

definition slide :: "(int \<Rightarrow> 'a) \<Rightarrow> int \<Rightarrow> int \<Rightarrow> int \<Rightarrow> 'a" where
  "slide a old_first new_first i = a (i - (new_first - old_first))"

lemma slide_eq: "slide a i i = a"
  by (rule ext) (simp add: slide_def)


(**** Rules for simplifying unwieldy case expressions ****)

lemma case_not_eq [simp]: "(case P of True \<Rightarrow> False | False \<Rightarrow> True) = (\<not> P)"
  by (cases P) simp_all

lemma case_conj_eq [simp]: "(case P of True \<Rightarrow> Q | False \<Rightarrow> False) = (P \<and> Q)"
  by (cases P) simp_all

lemma case_disj_eq [simp]: "(case P of True \<Rightarrow> True | False \<Rightarrow> Q) = (P \<or> Q)"
  by (cases P) simp_all

lemma if_trivial [simp]: "(if P then True else False) = P"
  by simp

lemma if_conj_eq [simp]: "(if P then Q else False) = (P \<and> Q)"
  by simp

end
