theory SPARK2014
imports Why3
begin

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


(**** _gnatprove_standard_th.Bitwise ****)

why3_consts
  "_gnatprove_standard_th.Bitwise.bitwise_and" = bitAND
  "_gnatprove_standard_th.Bitwise.bitwise_or" = bitOR
  "_gnatprove_standard_th.Bitwise.bitwise_xor" = bitXOR


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
  Standard__integer.to_int = integer_to_int
  Standard__integer.of_int = integer_of_int

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
  Standard__natural.to_int = natural_to_int
  Standard__natural.of_int = natural_of_int

why3_defs
  Standard__natural.in_range = natural_in_range_def

why3_thms
  Standard__natural.inversion_axiom = natural_to_int_inverse and
  Standard__natural.range_axiom = natural_to_int [simplified] and
  Standard__natural.coerce_axiom = natural_of_int_inverse [simplified]


(**** _gnatprove_standard.Array__1 ****)

type_synonym 'a array1 = "int \<Rightarrow> 'a"

abbreviation (input) array1_get :: "'a array1 \<Rightarrow> int \<Rightarrow> 'a" where
  "array1_get f \<equiv> f"

abbreviation (input) array1_set :: "'a array1 \<Rightarrow> int \<Rightarrow> 'a \<Rightarrow> 'a array1" where
  "array1_set f i x \<equiv> f(i := x)"

lemma Select_eq: "(m(i := a)) i = a"
  by simp

lemma Select_neq: "i \<noteq> j \<Longrightarrow> (m(i := a)) j = m j"
  by simp

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

why3_types
  "_gnatprove_standard.Array__1.map" = array1

why3_consts
  "_gnatprove_standard.Array__1.get" = array1_get
  "_gnatprove_standard.Array__1.set" = array1_set
  "_gnatprove_standard.Array__1.bool_eq" = array1_eq
  "_gnatprove_standard.Array__1.slide" = slide

why3_thms
  "_gnatprove_standard.Array__1.Select_eq" = Select_eq and
  "_gnatprove_standard.Array__1.Select_neq" = Select_neq and
  "_gnatprove_standard.Array__1.T__ada_array___equal_def" = array1_eq and
  "_gnatprove_standard.Array__1.slide_def" = slide_def and
  "_gnatprove_standard.Array__1.slide_eq" = slide_eq


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
