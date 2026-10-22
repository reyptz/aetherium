# EqSD — Problème d'Équilibrage Stœchiométrique Doré

**Statut : note de recherche.** Ce document fixe un modèle mathématique
vérifiable. Il sépare ce qui est démontré, ce qui est estimé de façon
reproductible, et ce qui reste ouvert. Ce n'est ni une preuve de sécurité, ni
une construction utilisable.

Fichiers associés :
- `research/eqsd_checks.py` — vérifications exactes (bibliothèque standard seule)
- `research/eqsd_estimate.py` — estimations reproductibles (lattice estimator)

---

## 1. Anneau

```
R    = ℤ[X] / (X² − X − 1)          anneau entier ; X joue le rôle de φ (φ² = φ + 1)
R_q  = 𝔽_q[X] / (X² − X − 1)        sa réduction modulo q
q    = 28657 = F₂₃                  nombre premier de Fibonacci
```

**Fait 1 (démontré).** `q ≡ 2 (mod 5)`. Le discriminant de `X² − X − 1` vaut 5,
qui n'est pas un carré modulo `q` (critère d'Euler : `5^((q−1)/2) ≡ −1`). Le
polynôme est donc irréductible sur `𝔽_q`, et `R_q ≅ 𝔽_{q²}` est un corps.
Vérifié par `eqsd_checks.py`.

**Représentation.** Un élément `a = a₀ + a₁X` est représenté par le vecteur
`(a₀, a₁)`. Puisque `X² = X + 1`, la multiplication par `a` agit sur `(b₀, b₁)`
par la matrice :

```
M(a) = [ a₀    a₁    ]          M(X) = [ 0  1 ]   (matrice de Fibonacci)
       [ a₁  a₀ + a₁ ]                 [ 1  1 ]
```

Les coefficients modulo `q` sont représentés de façon centrée, dans `(−q/2, q/2]`.

## 2. Convention de dimensions (unique)

Les dimensions de l'**anneau** sont `k × ℓ = 322 × 2242`. La matrice entière
**développée** `Â ∈ ℤ_q^(644 × 4484)` est obtenue en remplaçant chaque
coefficient `a_ij ∈ R_q` par le bloc `M(a_ij)`. Dans toute la suite :

| Symbole | Valeur | Sens |
|---|---|---|
| `k, ℓ` | 322, 2242 | dimensions sur `R_q` |
| `n̂ = 2k` | 644 | lignes entières (lois de conservation) |
| `m̂ = 2ℓ` | 4484 | colonnes entières (espèces) |

La **norme** est la norme `ℓ∞` sur le vecteur de coefficients dans `ℤ^m̂`.

## 3. Distributions

- **Matrice.** Modèle idéal : `A` uniforme sur `R_q^(k×ℓ)`. Réalisation :
  `A = Expand(graine)` par SHAKE256 avec échantillonnage par rejet, comme
  `ExpandA` dans ML-DSA. **Hypothèse H1** : la sortie d'`Expand` est
  indistinguable d'une matrice uniforme (modèle de l'oracle aléatoire). Toute
  affirmation ci-dessous sur `A` uniforme se transpose à la réalisation sous H1.
- **Secret.** `x ←$ {−1, 0, 1}^m̂`, coordonnées uniformes et indépendantes.
- **Clé publique.** `y = Â · x mod q ∈ ℤ_q^n̂`.

## 4. Problèmes

**EqSD-Coll(A, β)** — Donné `A`, trouver `z ∈ ℤ^m̂`, `z ≠ 0`, `‖z‖∞ ≤ β`, avec `Â z ≡ 0 (mod q)`.
C'est SIS∞ sur la matrice développée. Avec la structure, c'est Module-SIS de
degré 2, de dimensions `k × ℓ` sur `R_q`.

**EqSD-KR(A, y)** — Donné `(A, y = Âx)` avec `x` tiré selon la distribution du
§3, retrouver `x' ∈ {−1, 0, 1}^m̂` tel que `Âx' = y`.

**Lien entre les deux (démontré).** Deux secrets ternaires distincts `x ≠ x'`
de même clé publique donnent `z = x − x' ≠ 0`, `‖z‖∞ ≤ 2`, `Âz = 0`. Une
collision de clés est donc une solution d'EqSD-Coll pour `β = 2`.

## 5. Ce qui est démontré

**Fait 2 — Unicité de la clé (avec forte probabilité sur A).** Pour `z ≠ 0` à
coefficients `|z_i| < q`, l'image de `z` dans `R_q^ℓ` est non nulle. Comme
`R_q` est un corps et `A` uniforme, `A z` est uniforme sur `R_q^k`, donc
`Pr[Âz = 0] = q^(−n̂)`. Par union sur les `3^m̂ − 1` autres vecteurs ternaires :

```
E[nombre d'autres antécédents ternaires de y] ≤ 3^4484 · 28657^(−644) ≈ 2^(−2428.5)
```

Avec une probabilité écrasante sur `A`, le secret ternaire est unique.
Cela corrige l'argument « l'espace des secrets est plus petit que l'espace des
sorties », qui ne suffisait pas.

**Fait 3 — Forme normale (réécriture exacte).** Écrivons `Â = [Â₁ | Â₂]` avec
`Â₁` de taille `n̂ × n̂`, inversible avec probabilité `≈ 1 − q^(−2)` (matrice
`k × k` uniforme sur le corps `𝔽_{q²}`). Alors :

```
Â₁⁻¹ y = x₁ + (Â₁⁻¹ Â₂) x₂
```

En posant `b = Â₁⁻¹ y`, `A' = Â₁⁻¹ Â₂`, `s = x₂`, `e = x₁`, on obtient

```
b = A' s + e (mod q)        A' ∈ ℤ_q^(644 × 3840),  s ∈ {−1,0,1}^3840,  e ∈ {−1,0,1}^644
```

qui est la forme `b = As + e` de LWE, avec secret et erreur courts (« forme
normale »). Si `A` est uniforme, `A'` est uniforme et indépendante de `Â₁`.
Les deux formulations ont exactement les mêmes solutions : `x` est solution
d'EqSD-KR si et seulement si `(s, e) = (x₂, x₁)` est solution de cette instance.
C'est la même identité que la clé publique de ML-DSA, `t = A s₁ + s₂ = [A | I]·(s₁, s₂)`.

Portée exacte : c'est une équivalence **entre ces deux instances**, pas une
équivalence entre les problèmes SIS et LWE en général. L'instance obtenue est
atypique : 644 échantillons pour un secret de dimension 3840 (sous-déterminée),
régime peu étudié.

**Fait 4 — Rang plein.** Si `A` est de rang `k` sur `𝔽_{q²}`, alors `Â` est de
rang `2k = 644` sur `𝔽_q`, car le développement par blocs est la même
application linéaire vue sur `𝔽_q`. Le réseau `Λ⊥(Â)` a donc pour déterminant
`q^644`. Vérifié sur une instance tirée uniformément : rang 644.

## 6. Ce qui n'est pas démontré

1. **Réduction pire cas.** EqSD-Coll est une instance de Module-SIS. Les
   réductions connues (Ajtai 1996 pour SIS ; Langlois–Stehlé 2015 pour
   Module-SIS) ont des conditions précises sur `q`, la norme (souvent `ℓ₂`) et
   les dimensions. **Il reste à énoncer le théorème exact et à vérifier ses
   hypothèses pour ces paramètres.** La comparaison `q ≫ β√n̂` ne suffit pas.
2. **Distribution.** Une réduction pour le problème général ne donne pas la
   difficulté d'EqSD-KR sur la distribution ternaire du secret. La sécurité
   concrète de la clé vient de la cryptanalyse de cette distribution (§7).
3. **Structure dorée.** Aucune preuve que la structure `ℤ[φ]` (degré 2)
   n'ouvre pas une attaque plus efficace que sur SIS non structuré. Aucune
   attaque de ce type n'est connue en degré 2, mais c'est un constat, pas une
   preuve.
4. **Hypothèse H1** sur la génération de `A`. C'est une hypothèse de
   pseudo-aléa sur SHAKE256 dans ce rôle. Le fait qu'ML-DSA procède de même
   (`ExpandA`) est un précédent, pas une garantie transférée à EqSD.

**Correction d'une affirmation antérieure.** Il avait été écrit que la
récupération de clé « équivaut à LWE ». C'était imprécis. Le résultat exact est
le Fait 3 : une réécriture de l'instance en LWE sous forme normale. Les liens
généraux entre problèmes de sac à dos et LWE (Micciancio–Mol, CRYPTO 2011)
existent, mais sous des conditions qui n'ont pas été vérifiées ici.

## 7. Estimations reproductibles

**Outil** : lattice estimator, commit `e4333d9bf9ef42fd8a29651b0c559fba7ce0d834`,
SageMath 10.8.13 (passagemath). Appels exacts : `research/eqsd_estimate.py`.
Sortie complète : `research/eqsd_estimate_output.txt`.

**Norme.** L'instance est déclarée avec `norm=oo, length_bound=2`. L'estimateur
traite la norme `ℓ∞` directement, par une analyse probabiliste (MATZOV 2022 ;
spécification de Dilithium, p. 35). Il n'y a pas de conversion vers une borne
euclidienne.

**Structure.** L'estimateur modélise un réseau `Λ⊥(Â)` de dimension 4484 et de
déterminant `q^644` (Fait 4). Il suppose que ce réseau se comporte comme un
réseau aléatoire face à BKZ. C'est la même convention que pour les estimations
publiées de ML-KEM et ML-DSA, qui ignorent aussi leur structure de module. Ce
n'est pas une preuve pour la structure de degré 2 (§6.3).

**Calibration.** Avec le même outil, le mode `rough` donne environ 2²⁵⁵
(β = 874) pour ML-KEM-1024 et environ 2²⁵³ (β = 868) pour ML-DSA-87, en accord
avec les ordres de grandeur core-SVP publiés. Cela vérifie l'installation,
**pas** la pertinence du modèle pour EqSD.

**Collision : sensibilité au modèle**

| Appel | Modèle de coût | β_BKZ | Coût |
|---|---|---|---|
| `SIS.estimate.rough` | core-SVP | 3873 | ≈ 2¹¹³¹ |
| `SIS.lattice`, `RC.ADPS16` | core-SVP | 4335 | ≈ 2¹²⁶⁶ |
| `SIS.lattice`, défaut | défaut de l'outil (MATZOV) | 4479 | ≈ 2¹⁴⁰³ |

Le chiffre varie de 2¹¹³¹ à 2¹⁴⁰³ selon le modèle. Les tailles de bloc sont
proches de la dimension complète (4484), soit environ cinq fois au-delà de la
zone où l'outil a été calibré (β ≈ 870). **Ce sont des extrapolations
heuristiques, pas des niveaux de sécurité.** La seule lecture défendable : dans
les modèles d'attaque par réduction de réseau de cet outil, la collision exige
une réduction en dimension quasi complète.

**Récupération de clé : sécurité inconnue**

Pour l'instance du Fait 3, toutes les attaques modélisées renvoient `2^inf`.
Cela signifie seulement que l'outil n'a pas trouvé de coût fini dans cette
configuration. **Ce n'est pas un résultat positif de sécurité.**

Les normes 54,7 (norme typique du secret ternaire) et 70,7 (heuristique
gaussienne du réseau d'attaque) n'expliquent qu'une chose : pourquoi le
modèle uSVP ne s'applique pas, puisque le secret n'est pas exceptionnellement
court dans ce réseau. Elles ne mesurent le coût d'aucune attaque.

À étudier avant toute affirmation : attaques combinatoires sur secrets
ternaires (techniques de représentations), attaques hybrides (réduction et
recherche), décodage par ensembles d'information, et exploitation de la
distribution ternaire.

Les estimations grossières faites auparavant (2⁸²³ pour la collision, 2¹¹⁹⁷
pour la clé) sont **retirées**.

## 8. Tailles

| Objet | Taille |
|---|---|
| `y` (15 bits par coefficient) | 644 × 15 = 9660 bits, soit 1208 octets |
| Graine de `A` | 32 octets |
| **Clé publique** (`y` + graine) | **1240 octets** |
| `x`, codage idéal (log₂ 3 bits par valeur) | ≈ 888,4 octets |
| `x`, codage 2 bits par valeur | 1121 octets |

## 9. Points ouverts

1. Énoncer le théorème de réduction applicable et vérifier ses hypothèses (§6.1).
2. Étudier les attaques sur EqSD-KR listées au §7 ; aucun niveau de sécurité
   de la clé n'est connu.
3. Rendre la collision robuste au modèle : paramètres dans la zone calibrée, ou
   analyse au-delà.
4. Analyser la structure de degré 2 (§6.3).
5. Seulement ensuite : construire une signature, dont les bornes plus larges
   changeront fortement les estimations.
