theory LSC_HMAC_RIPEMD160_Authenticate
imports SPARK
begin

spark_open "$VCG_DIR/lsc_/hmac_ripemd160/authenticate.siv"

spark_vc function_authenticate_4
proof -
  from
    `0 \<le> message__index__subtype__1__first`
    `message__index__subtype__1__last \<le> 9007199254740991`
    `length \<le>
     (message__index__subtype__1__last - message__index__subtype__1__first + 1) * 512 mod
     18446744073709551616`
    `message__index__subtype__1__first \<le> message__index__subtype__1__last`
  have "message__index__subtype__1__first + length div 512 \<le> 9007199254740992"
    by (simp add: mod_pos_pos_trivial)
  with
    `0 \<le> length`
    `0 \<le> message__index__subtype__1__first`
  show ?thesis
    by (simp add: sdiv_pos_pos mod_pos_pos_trivial)
qed

spark_vc function_authenticate_5
proof -
  from
    `0 \<le> message__index__subtype__1__first`
    `message__index__subtype__1__last \<le> 9007199254740991`
    `length \<le>
     (message__index__subtype__1__last - message__index__subtype__1__first + 1) * 512 mod
     18446744073709551616`
    `message__index__subtype__1__first \<le> message__index__subtype__1__last`
    `0 \<le> length`
  show ?C2
    by (simp add: sdiv_pos_pos mod_pos_pos_trivial)
  show ?C3
  proof
    assume "length mod 512 \<noteq> 0"
    with `0 \<le> length`
    have "length div 512 * 512 < length div 512 * 512 + length mod 512"
      by (simp add: zmod_zdiv_equality')
    also from
      `0 \<le> message__index__subtype__1__first`
      `message__index__subtype__1__last \<le> 9007199254740991`
      `length \<le>
      (message__index__subtype__1__last - message__index__subtype__1__first + 1) * 512 mod
      18446744073709551616`
      `message__index__subtype__1__first \<le> message__index__subtype__1__last`
    have "length \<le>
      (message__index__subtype__1__last - message__index__subtype__1__first + 1) * 512"
      by (simp add: mod_pos_pos_trivial)
    finally have "length div 512 * 512 <
      (message__index__subtype__1__last - message__index__subtype__1__first + 1) * 512"
      by simp
    with `0 \<le> length`
    show "message__index__subtype__1__first + length sdiv 512 \<le>
      message__index__subtype__1__last"
      by (simp add: sdiv_pos_pos)
  qed
qed

spark_vc function_authenticate_11
  using
    `message__index__subtype__1__first <
     (message__index__subtype__1__first + length sdiv 512) mod 18446744073709551616`
    `(message__index__subtype__1__first + length sdiv 512) mod 18446744073709551616 - 1 <
     message__index__subtype__1__first`
  by auto

spark_vc function_authenticate_12
  using
    `0 \<le> message__index__subtype__1__first`
    `message__index__subtype__1__last \<le> 9007199254740991`
    `length \<le>
     (message__index__subtype__1__last - message__index__subtype__1__first + 1) * 512 mod
     18446744073709551616`
    `message__index__subtype__1__first \<le> message__index__subtype__1__last`
    `0 \<le> length`
  by (simp add: sdiv_pos_pos mod_pos_pos_trivial)

spark_end

end
