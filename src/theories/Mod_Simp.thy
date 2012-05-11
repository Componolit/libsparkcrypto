theory Mod_Simp
imports Main
begin

lemma plus_mod_cong:
  "(a::'a::semiring_div) mod m = a' mod m \<Longrightarrow> b mod m = b' mod m \<Longrightarrow>
   (a + b) mod m = (a' + b') mod m"
  by (simp add: mod_add_eq [of a b] mod_add_eq [of a' b'])

lemma diff_mod_cong:
  "(a::'a::ring_div) mod m = a' mod m \<Longrightarrow> b mod m = b' mod m \<Longrightarrow>
   (a - b) mod m = (a' - b') mod m"
  by (simp add: mod_diff_eq [of a b] mod_diff_eq [of a' b'])

lemma mult_mod_cong:
  "(a::'a::semiring_div) mod m = a' mod m \<Longrightarrow> b mod m = b' mod m \<Longrightarrow>
   (a * b) mod m = (a' * b') mod m"
  by (simp add: mod_mult_eq [of a b] mod_mult_eq [of a' b'])

lemma minus_mod_cong:
  "(a::'a::ring_div) mod m = a' mod m \<Longrightarrow>
   (- a) mod m = (- a') mod m"
  by (simp add: mod_minus_eq [of a] mod_minus_eq [of a'])

lemma mod_power_eq:
  "(a::'a::semiring_div) ^ k mod m = (a mod m) ^ k mod m"
proof (induct k)
  case (Suc l)
  then show ?case
    by (simp add: mod_mult_eq [of a "a ^ l"])
      (simp add: mod_mult_right_eq [symmetric])
qed simp

lemma power_mod_cong:
  "(a::'a::semiring_div) mod m = a' mod m \<Longrightarrow>
   a ^ k mod m = a' ^ k mod m"
  by (simp add: mod_power_eq [of a] mod_power_eq [of a'])

lemma mod_self_cong:
  "(m::'a::semiring_div) mod m = 0 mod m"
    by simp

simproc_setup pull_mod ("a mod b") = {*
let

fun has_mod rng m s =
  m aconv s orelse (case s of
      Const (@{const_name mod}, _) $ _ $ m' => m aconv m'
    | Const (@{const_name plus}, _) $ t $ u =>
        has_mod rng m t orelse has_mod rng m u
    | Const (@{const_name minus}, _) $ t $ u =>
        rng andalso (has_mod rng m t orelse has_mod rng m u)
    | Const (@{const_name times}, _) $ t $ u =>
        has_mod rng m t orelse has_mod rng m u
    | Const (@{const_name power}, _) $ t $ u =>
        has_mod rng m t
    | Const (@{const_name uminus}, _) $ t =>
        rng andalso has_mod rng m t
    | _ => false);

fun pull_mod rng cmod cm ct =
  if term_of cm aconv term_of ct then
    Drule.instantiate' [SOME (ctyp_of_term ct)] [SOME ct]
      @{thm mod_self_cong}
  else if has_mod rng (term_of cm) (term_of ct) then
    case term_of ct of
      Const (@{const_name mod}, _) $ _ $ _ =>
        let val (cx, cm) = Thm.dest_binop ct
        in Drule.instantiate' [SOME (ctyp_of_term cx)] [SOME cx, SOME cm]
          @{thm mod_mod_trivial}
        end
    | Const (@{const_name plus}, _) $ _ $ _ =>
        let val (cl, cr) = Thm.dest_binop ct
        in @{thm plus_mod_cong} OF
          [pull_mod rng cmod cm cl, pull_mod rng cmod cm cr]
        end
    | Const (@{const_name minus}, _) $ _ $ _ =>
        let val (cl, cr) = Thm.dest_binop ct
        in @{thm diff_mod_cong} OF
          [pull_mod rng cmod cm cl, pull_mod rng cmod cm cr]
        end
    | Const (@{const_name times}, _) $ _ $ _ =>
        let val (cl, cr) = Thm.dest_binop ct
        in @{thm mult_mod_cong} OF
          [pull_mod rng cmod cm cl, pull_mod rng cmod cm cr]
        end
    | Const (@{const_name power}, _) $ _ $ _ =>
        let val (cl, cr) = Thm.dest_binop ct
        in Drule.instantiate' [] [NONE, NONE, NONE, SOME cr]
          @{thm power_mod_cong} OF [pull_mod rng cmod cm cl]
        end
    | Const (@{const_name uminus}, _) $ _ =>
        let val cu = Thm.dest_arg ct
        in @{thm minus_mod_cong} OF [pull_mod rng cmod cm cu] end
    | _ => raise Fail "pull_mod"
  else
    Drule.instantiate' [SOME (ctyp_of_term ct)]
      [SOME (Drule.list_comb (cmod, [ct, cm]))] refl;

fun pull_mod_proc _ ss ct = (case term_of ct of
    Const (@{const_name mod}, Type (_, [T, _])) $ u $ m =>
      let val rng = Sign.of_sort
        (Proof_Context.theory_of (Simplifier.the_context ss))
        (T, @{sort ring})
      in
        if has_mod rng m u then
          let val (cmod, [cu, cm]) = Drule.strip_comb ct
          in SOME (mk_meta_eq (pull_mod rng cmod cm cu)) end
        else NONE
      end
  | _ => NONE);

in pull_mod_proc end;
*}


(*** Examples ***)

lemma "(((a::int) + b) + (c mod m + d)) mod m = ((a + b) + (c + d)) mod m"
  by simp

lemma "(((a::int) + b mod m) + (c mod m + d)) mod m = ((a + b) + (c + d)) mod m"
  by simp

lemma "(((a::int) + b mod m) + (c mod m - d)) mod m = ((a + b) + (c - d)) mod m"
  by simp

lemma "(((a::nat) + b mod m) + (c mod m - d)) mod m = ((a + b) + (c mod m - d)) mod m"
  by simp

lemma "(a::int) * ((b * (c mod m)) ^ k) mod m = a * ((b * c) ^ k) mod m"
  by simp

lemma "(((a::int) + b mod m) + (c mod m + d * m)) mod m = ((a + b) + c) mod m"
  by simp

end


