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

EqSD-KR est donc **exactement** une instance LWE sous forme normale : secret
`x₂` (3840 coordonnées ternaires), 644 échantillons, erreur `x₁` (ternaire).
C'est une réécriture bijective de l'instance, pas une réduction entre problèmes
généraux.

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
4. **Hypothèse H1** sur la génération de `A`.

**Correction d'une affirmation antérieure.** Il avait été écrit que la
récupération de clé « équivaut à LWE ». C'était imprécis. Le résultat exact est
le Fait 3 : une réécriture de l'instance en LWE sous forme normale. Les liens
généraux entre problèmes de sac à dos et LWE (Micciancio–Mol, CRYPTO 2011)
existent, mais sous des conditions qui n'ont pas été vérifiées ici.

## 7. Estimations reproductibles

**Outil** : lattice estimator, commit `e4333d9bf9ef42fd8a29651b0c559fba7ce0d834`,
sur SageMath 10.8.13 (passagemath). Mode `rough` : modèle core-SVP, coût
ADPS16 `2^(0.292β)`. La structure de degré 2 est ignorée : les instances sont
estimées comme SIS/LWE non structurés de dimensions développées.

**Calibration** (même outil, même mode) :

| Schéma | Publié | Obtenu |
|---|---|---|
| ML-KEM-1024 (LWE) | ≈ 2²⁵⁶ | β = 874, ≈ 2²⁵⁵·² |
| ML-DSA-87 (MSIS) | ≈ 2²⁵² | β = 868, ≈ 2²⁵³·⁵ |

**EqSD :**

| Instance | Paramètres | Résultat |
|---|---|---|
| Collision | SIS∞, n = 644, m = 4484, q = 28657, β = 2 | β_BKZ = 3873, ≈ 2¹¹³⁰·⁹ (classique, core-SVP) |
| Récupération de clé | LWE forme normale, n = 3840, m = 644, secret et erreur ternaires | **hors modèle** : toutes les attaques renvoient `2^inf` |

**Lecture du résultat « hors modèle ».** `2^inf` ne signifie pas une sécurité
infinie. Le vecteur cible `(x₂, x₁)` a une norme `≈ √(4484 · 2/3) ≈ 54,7`. Le
plus court vecteur attendu du réseau d'attaque (dimension 4485, déterminant
`q^644`) a une norme `≈ √(4485/(2πe)) · q^(644/4485) ≈ 70,7`. Le secret n'est
donc pas assez court par rapport au réseau pour que l'attaque uSVP s'applique,
et l'outil ne trouve aucune taille de bloc qui réussisse. **Aucun chiffre de
sécurité n'est revendiqué pour EqSD-KR** tant qu'une attaque adaptée à ce régime
n'a pas été modélisée.

**Non modélisé :** attaques hybrides (réduction et recherche combinées),
attaques combinatoires sur secrets ternaires, attaques algébriques, et toute
attaque exploitant la structure de degré 2.

Les estimations grossières faites auparavant (2⁸²³ pour la collision, 2¹¹⁹⁷
pour la clé) sont **remplacées** par ce tableau.

## 8. Tailles

| Objet | Taille |
|---|---|
| `y` (15 bits par coefficient) | 644 × 15 = 9660 bits = 1207,5 octets |
| `x`, codage idéal (log₂ 3 bits par valeur) | ≈ 888,4 octets |
| `x`, codage 2 bits par valeur | 1121 octets |

## 9. Points ouverts

1. Énoncer le théorème de réduction applicable et vérifier ses hypothèses (§6.1).
2. Modéliser une attaque adaptée à EqSD-KR dans ce régime (§7).
3. Analyser la structure de degré 2 (§6.3).
4. Seulement ensuite : construire une signature, dont les bornes plus larges
   changeront fortement les estimations.
