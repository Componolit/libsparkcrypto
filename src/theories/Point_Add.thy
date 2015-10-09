theory Point_Add
imports LibSPARKcrypto
begin

lemma add_less_mod: "(x::int) < m \<Longrightarrow> y < m \<Longrightarrow>
  x + y - m * num_of_bool (b \<le> x + y) -
  m + m * num_of_bool (x + y - m * num_of_bool (b \<le> x + y) < m) < m"
  by (simp split add: num_of_bool_split)

lemma sub_less_mod: "(x::int) < m \<Longrightarrow> y < m \<Longrightarrow> 0 \<le> y \<Longrightarrow>
  x - y + m * num_of_bool (x < y) < m"
  by (simp split add: num_of_bool_split)

end
