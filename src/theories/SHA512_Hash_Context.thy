theory SHA512_Hash_Context
imports SPARK
begin

spark_open "$VCG_DIR/lsc_/sha512/hash_context"

spark_vc procedure_hash_context_4
proof -
  from
    `message__index__subtype__1__last \<le> 18014398509481983`
    `length \<le>
     (message__index__subtype__1__last - message__index__subtype__1__first + 1) * 1024`
  have "message__index__subtype__1__first + length div 1024 \<le> 18014398509481984"
    by simp
  with
    `0 \<le> length`
    `0 \<le> message__index__subtype__1__first`
  show ?thesis
    by (simp add: sdiv_pos_pos mod_pos_pos_trivial)
qed

spark_vc procedure_hash_context_5
proof -
  from
    `length \<le>
     (message__index__subtype__1__last - message__index__subtype__1__first + 1) * 1024`
    `0 \<le> length`
  show ?C1
    by (simp add: sdiv_pos_pos)
  show ?C2
  proof
    assume "length mod 1024 \<noteq> 0"
    with `0 \<le> length`
    have "length div 1024 * 1024 < length div 1024 * 1024 + length mod 1024"
      by (simp add: zmod_zdiv_equality')
    with `length \<le>
      (message__index__subtype__1__last - message__index__subtype__1__first + 1) * 1024`
    have "length div 1024 * 1024 <
      (message__index__subtype__1__last - message__index__subtype__1__first + 1) * 1024"
      by simp
    with `0 \<le> length`
    show "message__index__subtype__1__first + length sdiv 1024 \<le>
      message__index__subtype__1__last"
      by (simp add: sdiv_pos_pos)
  qed
qed

spark_vc procedure_hash_context_11
  using
    `message__index__subtype__1__first <
     (message__index__subtype__1__first + length sdiv 1024) mod 18446744073709551616`
    `(message__index__subtype__1__first + length sdiv 1024) mod 18446744073709551616 - 1 <
     message__index__subtype__1__first`
  by auto

spark_vc procedure_hash_context_12
  using
    `0 \<le> message__index__subtype__1__first`
    `message__index__subtype__1__last \<le> 18014398509481983`
    `length \<le>
     (message__index__subtype__1__last - message__index__subtype__1__first + 1) * 1024`
    `0 \<le> length`
  by (simp add: sdiv_pos_pos mod_pos_pos_trivial)

spark_end

end
