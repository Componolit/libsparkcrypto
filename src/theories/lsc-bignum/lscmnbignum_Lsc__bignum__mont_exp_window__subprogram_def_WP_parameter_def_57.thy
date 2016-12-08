theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_57
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_57.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "a_last - a_first + 1"
  let ?e = "num_of_big_int (word32_to_int \<circ> elts e) e_first (e_last - e_first + 1)"

  have "?e div 2 ^ nat (uint i1 - s3) mod 2 ^ nat (s3 + 1) < 2 ^ nat (s3 + 1)"
    by simp
  also from `s3 + 1 \<le> k + 1`
  have "(2::int) ^ nat (s3 + 1) \<le> 2 ^ nat (k + 1)"
    by simp
  with `natural_in_range k`
  have "(2::int) ^ nat (s3 + 1) \<le> 2 * 2 ^ nat k"
    by (simp add: nat_add_distrib natural_in_range_def)
  finally have "?e div 2 ^ nat (uint i1 - s3) mod
    2 ^ nat (s3 + 1) div 2 < 2 ^ nat k"
    by simp
  with `a_first < a_last`
  have "?e div 2 ^ nat (uint i1 - s3) mod 2 ^ nat (s3 + 1) div 2 * ?L \<le>
    (2 ^ nat k - 1) * ?L"
    by simp
  with
    `aux4_first + (2 ^ nat k * ?L - 1) \<le> \<lfloor>aux4__last\<rfloor>\<^sub>\<int>`
    `(math_int_from_word w1 = _) = _`
  show ?thesis by (simp add: left_diff_distrib mk_bounds_snd ediv_def
    BV32.facts.to_uint_lsr [of _ 1, simplified])
qed

why3_end

end
