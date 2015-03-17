theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_15
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_15.xml"

why3_vc WP_parameter_def
proof -
  from `1 \<le> h` `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
  have "0 \<le> (h - 1) * (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1)"
    by simp
  moreover from `h \<le> 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> - 1` `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
  have "(h - 1) * (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1) \<le>
    2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> * (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1) - 1"
    by simp
  with `\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + (2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> * (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1) - 1) \<le>
    \<lfloor>aux4_last\<rfloor>\<^sub>\<int>`
  have "\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + (h - 1) * (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1) \<le> \<lfloor>aux4_last\<rfloor>\<^sub>\<int>"
    by simp
  ultimately show ?thesis using
    `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
    integer_to_int_upper [of aux4_last]
    natural_to_int_lower [of aux4_first1]
    by (simp add: integer_in_range_def)
qed

why3_end

end
