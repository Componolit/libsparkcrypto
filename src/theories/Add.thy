theory Add
imports LibSPARKcrypto
begin

lemma div_mod_eq:
  "z + (x::int) * (y mod b) + b * x * (y div b) = z + x * y"
  (is "?l = ?r")
proof -
  have "?l = z + x * (y mod b + b * (y div b))"
    by (simp only: ring_distribs mult_ac)
  also have "... = ?r" by (simp add: ring_distribs)
  finally show ?thesis .
qed

lemma zdiv_geq: "0 < (n::int) \<Longrightarrow> n \<le> m \<Longrightarrow> m div n = (m - n) div n + 1"
  by (simp add: div_add_self2 [symmetric])

lemma le_zmod_geq: "(n::int) \<le> m \<Longrightarrow> m mod n = (m - n) mod n"
  by (simp add: mod_add_self2 [symmetric, of "m - n"])

lemma add_carry:
  "0 \<le> a \<Longrightarrow> 0 \<le> b \<Longrightarrow> a < B \<Longrightarrow> b < B \<Longrightarrow>
   num_of_bool ((a + b + num_of_bool c) mod B < a \<or>
     (a + b + num_of_bool c) mod B = a \<and> c) =
   (a + b + num_of_bool c) div B"
  by (cases "a + b + num_of_bool c < B")
    (auto simp add: mod_pos_pos_trivial div_pos_pos_trivial zdiv_geq
       le_zmod_geq not_less simp del: minus_mod_self2
       split add: num_of_bool_split)

end
