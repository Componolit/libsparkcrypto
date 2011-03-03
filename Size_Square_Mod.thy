theory Size_Square_Mod
imports Bignum
begin

spark_open "out/bignum/size_square_mod.siv"

spark_vc procedure_size_square_mod_6
  using `m_first \<le> m_last` H10 H21
  by (simp add: num_of_lint_all0 mod_pos_pos_trivial del: num_of_lint_sum)

lemma mod_eq:
  assumes "(0::int) \<le> x" and "x < m" and "m < r" and "r \<le> x * 2"
  shows "(x * 2) mod m = ((x * 2) mod r - m) mod r"
proof -
  have "(x * 2) mod m = (x * 2 - m) mod m"
    by simp
  also from `x < m` `m < r` `r \<le> x * 2`
  have "0 \<le> x * 2 - m" "x * 2 - m < m" by simp_all
  then have "(x * 2 - m) mod m = x * 2 - m"
    by (rule mod_pos_pos_trivial)
  also from `0 \<le> x * 2 - m` `x * 2 - m < m` `m < r`
  have "\<dots> = ((x * 2) mod r - m) mod r"
    by (simp add: mod_pos_pos_trivial)
  finally show ?thesis .
qed

lemma mod_eq':
  assumes "(x::int) < m" and "m < r" and "m \<le> x * 2"
  shows "(x * 2) mod m = (x * 2 - m) mod r"
proof -
  have "(x * 2) mod m = (x * 2 - m) mod m"
    by simp
  also from `x < m` `m \<le> x * 2`
  have "0 \<le> x * 2 - m" "x * 2 - m < m" by simp_all
  then have "(x * 2 - m) mod m = x * 2 - m"
    by (rule mod_pos_pos_trivial)
  also from `0 \<le> x * 2 - m` `x * 2 - m < m` `m < r`
  have "\<dots> = (x * 2 - m) mod r"
    by (simp add: mod_pos_pos_trivial)
  finally show ?thesis .
qed

lemma pow_plus1: "0 \<le> i \<Longrightarrow> (b::int) ^ nat i * b = b ^ nat (i + 1)"
  by (simp add: nat_add_distrib)

spark_vc procedure_size_square_mod_8
proof -
  let ?l = "(m_last - m_first + 1)"
  let ?R = "Base ^ nat ?l"
  let ?r = "num_of_big_int r r_first ?l"
  let ?m = "num_of_big_int m m_first ?l"
  note r_first_lower = `r__index__subtype__1__first \<le> r_first`
  note r_last_upper = `r_first + (m_last - m_first) \<le> r__index__subtype__1__last`
  note r2_r3 = [[fact "num_of_big_int r__2 _ _ - _ = _", simplified pow_simp_Base]]
  note r3_in_range = [[fact "bounds _ _ _ _ r__3"]]
  note r = [[fact "num_of_big_int r _ _ = _"]]
  note m_ge_1 = `1 < num_of_big_int m m_first ?l`
  note m_in_range = [[fact "bounds _ _ _ _ m"]]
  note m_first_lower = `m__index__subtype__1__first \<le> m_first`
  note m_last_upper = `m_last \<le> m__index__subtype__1__last`
  note r_in_range = [[fact "bounds _ _ _ _ r"]]
  note r_r2 = [[fact "num_of_big_int r _ _ * 2 = _", simplified pow_simp_Base]]
  note r2_in_range = [[fact "bounds _ _ _ _ r__2"]]
  note less = [[fact "_ \<longrightarrow> less r__2 _ _ m _ = _"]]
  note carry_or_not_less =
    `carry__2 \<or> \<not> less r__2 r_first (r_first + (m_last - m_first)) m m_first`

  from r_first_lower r_last_upper r2_r3 r3_in_range
  have r_minus_m: "(num_of_big_int r__2 r_first ?l - ?m) mod ?R =
    num_of_big_int r__3 r_first ?l"
    by (simp add: mod_diff_right_eq [of _ "?R * num_of_bool carry__3"]
      num_of_lint_lower num_of_lint_upper mod_pos_pos_trivial)
  from r m_ge_1 have "?r < ?m" by simp
  from m_in_range m_first_lower m_last_upper have "?m < ?R"
    by (simp add: num_of_lint_upper)
  show ?thesis
  proof (cases carry__2)
    case True
    from r_first_lower r_last_upper r_in_range have "0 \<le> ?r"
      by (simp add: num_of_lint_lower)
    moreover note `?r < ?m` `?m < ?R`
    moreover from True r_first_lower r_last_upper r_r2 r2_in_range
    have "?R \<le> ?r * 2" by (simp add: num_of_lint_lower)
    ultimately have "(?r * 2) mod ?m = ((?r * 2) mod ?R - ?m) mod ?R"
      by (rule mod_eq)
    also from r_first_lower r_last_upper r_r2 r2_in_range
    have "(?r * 2) mod ?R = num_of_big_int r__2 r_first ?l"
      by (simp add: num_of_lint_lower num_of_lint_upper mod_pos_pos_trivial)
    also note r_minus_m
    finally show ?thesis using r `m_first \<le> loop__1__i`
      by (simp add: zmod_simps pow_plus1) (simp only: sign_simps add_ac)
  next
    case False
    from False r_r2 have r2: "num_of_big_int r__2 r_first ?l = ?r * 2"
      by simp
    with False less carry_or_not_less have "?m \<le> ?r * 2" by simp
    with `?r < ?m` `?m < ?R` have "(?r * 2) mod ?m = (?r * 2 - ?m) mod ?R"
      by (rule mod_eq')
    then show ?thesis using H1 `m_first \<le> loop__1__i` r_minus_m r2
      by (simp add: zmod_simps pow_plus1) (simp only: sign_simps add_ac)
  qed
qed

spark_vc procedure_size_square_mod_9
proof -
  let ?l = "(m_last - m_first + 1)"
  let ?r = "num_of_big_int r r_first ?l"
  let ?m = "num_of_big_int m m_first ?l"
  note r_first_lower = `r__index__subtype__1__first \<le> r_first`
  note r_last_upper = `r_first + (m_last - m_first) \<le> r__index__subtype__1__last`
  note r = [[fact "num_of_big_int r _ _ = _"]]
  note r_r2 = [[fact "num_of_big_int r _ _ * 2 = _", simplified pow_simp_Base]]
  note r2_in_range = [[fact "bounds _ _ _ _ r__2"]]
  note less = [[fact "num_of_big_int r__2 _ _ < num_of_big_int m _ _"]]

  from r_r2 less r2_in_range r_first_lower r_last_upper
  have "num_of_big_int r__2 r_first ?l = (?r * 2) mod ?m"
    by (simp add: num_of_lint_lower mod_pos_pos_trivial)
  then show ?thesis using r `m_first \<le> loop__1__i`
    by (simp add: zmod_simps pow_plus1) (simp only: sign_simps add_ac)
qed

spark_vc procedure_size_square_mod_13
proof -
  let ?l = "(m_last - m_first + 1)"
  let ?R = "Base ^ nat ?l"
  let ?r = "num_of_big_int r r_first ?l"
  let ?m = "num_of_big_int m m_first ?l"
  note r_first_lower = `r__index__subtype__1__first \<le> r_first`
  note r_last_upper = `r_first + (m_last - m_first) \<le> r__index__subtype__1__last`
  note r2_r3 = [[fact "num_of_big_int r__2 _ _ - _ = _", simplified pow_simp_Base]]
  note r3_in_range = [[fact "bounds _ _ _ _ r__3"]]
  note r = [[fact "num_of_big_int r _ _ = _"]]
  note m_ge_1 = `1 < num_of_big_int m m_first ?l`
  note m_in_range = [[fact "bounds _ _ _ _ m"]]
  note m_first_lower = `m__index__subtype__1__first \<le> m_first`
  note m_last_upper = `m_last \<le> m__index__subtype__1__last`
  note r_in_range = [[fact "bounds _ _ _ _ r"]]
  note r_r2 = [[fact "num_of_big_int r _ _ * 2 = _", simplified pow_simp_Base]]
  note r2_in_range = [[fact "bounds _ _ _ _ r__2"]]
  note less = [[fact "_ \<longrightarrow> less r__2 _ _ m _ = _"]]
  note carry_or_not_less =
    `carry__2 \<or> \<not> less r__2 r_first (r_first + (m_last - m_first)) m m_first`

  from r_first_lower r_last_upper r2_r3 r3_in_range
  have r_minus_m: "(num_of_big_int r__2 r_first ?l - ?m) mod ?R =
    num_of_big_int r__3 r_first ?l"
    by (simp add: mod_diff_right_eq [of _ "?R * num_of_bool carry__3"]
      num_of_lint_lower num_of_lint_upper mod_pos_pos_trivial)
  from r m_ge_1 have "?r < ?m" by simp
  from m_in_range m_first_lower m_last_upper have "?m < ?R"
    by (simp add: num_of_lint_upper)
  show ?thesis
  proof (cases carry__2)
    case True
    from r_first_lower r_last_upper r_in_range have "0 \<le> ?r"
      by (simp add: num_of_lint_lower)
    moreover note `?r < ?m` `?m < ?R`
    moreover from True r_first_lower r_last_upper r_r2 r2_in_range
    have "?R \<le> ?r * 2" by (simp add: num_of_lint_lower)
    ultimately have "(?r * 2) mod ?m = ((?r * 2) mod ?R - ?m) mod ?R"
      by (rule mod_eq)
    also from r_first_lower r_last_upper r_r2 r2_in_range
    have "(?r * 2) mod ?R = num_of_big_int r__2 r_first ?l"
      by (simp add: num_of_lint_lower num_of_lint_upper mod_pos_pos_trivial)
    also note r_minus_m
    finally show ?thesis using r `m_first \<le> loop__1__i` `0 \<le> loop__2__j`
      by (simp add: zmod_simps pow_plus1) (simp only: sign_simps add_ac)
  next
    case False
    from False r_r2 have r2: "num_of_big_int r__2 r_first ?l = ?r * 2"
      by simp
    with False less carry_or_not_less have "?m \<le> ?r * 2" by simp
    with `?r < ?m` `?m < ?R` have "(?r * 2) mod ?m = (?r * 2 - ?m) mod ?R"
      by (rule mod_eq')
    then show ?thesis using H1 `m_first \<le> loop__1__i` `0 \<le> loop__2__j` r_minus_m r2
      by (simp add: zmod_simps pow_plus1) (simp only: sign_simps add_ac)
  qed
qed

spark_vc procedure_size_square_mod_14
proof -
  let ?l = "(m_last - m_first + 1)"
  let ?r = "num_of_big_int r r_first ?l"
  let ?m = "num_of_big_int m m_first ?l"
  note r_first_lower = `r__index__subtype__1__first \<le> r_first`
  note r_last_upper = `r_first + (m_last - m_first) \<le> r__index__subtype__1__last`
  note r = [[fact "num_of_big_int r _ _ = _"]]
  note r_r2 = [[fact "num_of_big_int r _ _ * 2 = _", simplified pow_simp_Base]]
  note r2_in_range = [[fact "bounds _ _ _ _ r__2"]]
  note less = [[fact "num_of_big_int r__2 _ _ < num_of_big_int m _ _"]]

  from r_r2 less r2_in_range r_first_lower r_last_upper
  have "num_of_big_int r__2 r_first ?l = (?r * 2) mod ?m"
    by (simp add: num_of_lint_lower mod_pos_pos_trivial)
  then show ?thesis using r `m_first \<le> loop__1__i` `0 \<le> loop__2__j`
    by (simp add: zmod_simps pow_plus1) (simp only: sign_simps add_ac)
qed

spark_vc procedure_size_square_mod_16
  using `r__index__subtype__1__first \<le> r_first`
    `r_first \<le> r__index__subtype__1__last `
    `r__index__subtype__1__first \<le> r_first + (m_last - m_first)`
    `r_first + (m_last - m_first) \<le> r__index__subtype__1__last`
    `m__index__subtype__1__first \<le> m_first`
    `m_first \<le> m__index__subtype__1__last`
    `m__index__subtype__1__first \<le> m_last`
    `m_last \<le> m__index__subtype__1__last`
    `m_first \<le> m_last`
  by simp

spark_vc procedure_size_square_mod_20
proof -
  let ?l = "(m_last - m_first + 1)"
  let ?R = "Base ^ nat ?l"
  let ?r = "num_of_big_int r r_first ?l"
  let ?m = "num_of_big_int m m_first ?l"
  note r_first_lower = `r__index__subtype__1__first \<le> r_first`
  note r_last_upper = `r_first + (m_last - m_first) \<le> r__index__subtype__1__last`
  note r2_r3 = [[fact "num_of_big_int r__2 _ _ - _ = _", simplified pow_simp_Base]]
  note r3_in_range = [[fact "bounds _ _ _ _ r__3"]]
  note r = [[fact "num_of_big_int r _ _ = _"]]
  note m_ge_1 = `1 < num_of_big_int m m_first ?l`
  note m_in_range = [[fact "bounds _ _ _ _ m"]]
  note m_first_lower = `m__index__subtype__1__first \<le> m_first`
  note m_last_upper = `m_last \<le> m__index__subtype__1__last`
  note r_in_range = [[fact "bounds _ _ _ _ r"]]
  note r_r2 = [[fact "num_of_big_int r _ _ * 2 = _", simplified pow_simp_Base]]
  note r2_in_range = [[fact "bounds _ _ _ _ r__2"]]
  note less = [[fact "_ \<longrightarrow> less r__2 _ _ m _ = _"]]
  note carry_or_not_less =
    `carry__2 \<or> \<not> less r__2 r_first (r_first + (m_last - m_first)) m m_first`

  from r_first_lower r_last_upper r2_r3 r3_in_range
  have r_minus_m: "(num_of_big_int r__2 r_first ?l - ?m) mod ?R =
    num_of_big_int r__3 r_first ?l"
    by (simp add: mod_diff_right_eq [of _ "?R * num_of_bool carry__3"]
      num_of_lint_lower num_of_lint_upper mod_pos_pos_trivial)
  from r m_ge_1 have "?r < ?m" by simp
  from m_in_range m_first_lower m_last_upper have "?m < ?R"
    by (simp add: num_of_lint_upper)
  show ?thesis
  proof (cases carry__2)
    case True
    from r_first_lower r_last_upper r_in_range have "0 \<le> ?r"
      by (simp add: num_of_lint_lower)
    moreover note `?r < ?m` `?m < ?R`
    moreover from True r_first_lower r_last_upper r_r2 r2_in_range
    have "?R \<le> ?r * 2" by (simp add: num_of_lint_lower)
    ultimately have "(?r * 2) mod ?m = ((?r * 2) mod ?R - ?m) mod ?R"
      by (rule mod_eq)
    also from r_first_lower r_last_upper r_r2 r2_in_range
    have "(?r * 2) mod ?R = num_of_big_int r__2 r_first ?l"
      by (simp add: num_of_lint_lower num_of_lint_upper mod_pos_pos_trivial)
    also note r_minus_m
    finally show ?thesis using r `m_first \<le> m_last`
      by (simp add: zmod_simps pow_plus1) (simp only: sign_simps add_ac)
  next
    case False
    from False r_r2 have r2: "num_of_big_int r__2 r_first ?l = ?r * 2"
      by simp
    with False less carry_or_not_less have "?m \<le> ?r * 2" by simp
    with `?r < ?m` `?m < ?R` have "(?r * 2) mod ?m = (?r * 2 - ?m) mod ?R"
      by (rule mod_eq')
    then show ?thesis using H1 `m_first \<le> m_last` r_minus_m r2
      by (simp add: zmod_simps pow_plus1) (simp only: sign_simps add_ac)
  qed
qed

spark_vc procedure_size_square_mod_21
proof -
  let ?l = "(m_last - m_first + 1)"
  let ?r = "num_of_big_int r r_first ?l"
  let ?m = "num_of_big_int m m_first ?l"
  note r_first_lower = `r__index__subtype__1__first \<le> r_first`
  note r_last_upper = `r_first + (m_last - m_first) \<le> r__index__subtype__1__last`
  note r = [[fact "num_of_big_int r _ _ = _"]]
  note r_r2 = [[fact "num_of_big_int r _ _ * 2 = _", simplified pow_simp_Base]]
  note r2_in_range = [[fact "bounds _ _ _ _ r__2"]]
  note less = [[fact "num_of_big_int r__2 _ _ < num_of_big_int m _ _"]]

  from r_r2 less r2_in_range r_first_lower r_last_upper
  have "num_of_big_int r__2 r_first ?l = (?r * 2) mod ?m"
    by (simp add: num_of_lint_lower mod_pos_pos_trivial)
  then show ?thesis using r `m_first \<le> m_last`
    by (simp add: zmod_simps pow_plus1) (simp only: sign_simps add_ac)
qed

spark_end

end
