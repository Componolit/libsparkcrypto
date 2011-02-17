theory Facts
imports Main
begin

ML {*
local

fun potential_facts ctxt prop =
  Facts.could_unify (ProofContext.facts_of ctxt) (Term.strip_all_body prop);

in

fun fact_attrib x =
  Scan.lift (Parse.string >> (fn s =>
    Thm.rule_attribute (fn context => fn _ =>
      let
        val ctxt = Context.proof_of context |>
          ProofContext.set_mode ProofContext.mode_default |>
          ProofContext.allow_dummies;
        val (prop, _) = Term.replace_dummy_patterns
          (singleton (Variable.polymorphic ctxt)
             (Syntax.read_prop ctxt s)) 1;

        fun prove_fact th =
          Goal.prove ctxt [] [] prop (K (ALLGOALS (ProofContext.fact_tac [th])))
      in
        case distinct Thm.eq_thm_prop
          (map_filter (try prove_fact) (potential_facts ctxt prop)) of
          [res] => res
        | [] => error ("Failed to retrieve literal fact:\n" ^
            Syntax.string_of_term ctxt prop)
        | _ => error ("Ambiguous fact specification:\n" ^
            Syntax.string_of_term ctxt prop)
      end))) x;

end;        
*}

attribute_setup fact =
  {* fact_attrib *}
  {* Retrieve facts from context *}

abbreviation (parse) bounds :: "int \<Rightarrow> int \<Rightarrow> ('a::ord) \<Rightarrow> 'a \<Rightarrow> (int \<Rightarrow> 'a) \<Rightarrow> bool" where
  "bounds k l x y a \<equiv> \<forall>i. k \<le> i \<and> i \<le> l \<longrightarrow> x \<le> a i \<and> a i \<le> y"

end
