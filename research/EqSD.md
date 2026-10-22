# EqSD — Problème d'Équilibrage Stœchiométrique Doré

**Statut : note de recherche.** Ce document fixe un modèle mathématique
vérifiable et sépare ce qui est démontré, ce qui est estimé de façon
reproductible, et ce qui reste ouvert. Ce n'est ni une preuve de sécurité, ni
une construction utilisable.

Fichiers associés :
- `research/eqsd_checks.py` — vérifications exactes (bibliothèque standard seule)
- `research/eqsd_estimate.py` — estimations reproductibles (lattice estimator)
- `research/eqsd_estimate_output.txt` — sortie complète de l'estimateur

**Historique.** Une version antérieure utilisait une matrice 644 × 4484. Ce
régime (644 équations pour 3840 inconnues) était trop peu étudié pour être
estimé : la récupération de clé y était inestimable et la collision n'était
qu'une extrapolation (de 2¹¹³¹ à 2¹⁴⁰³ selon le modèle). Il est abandonné au
profit du régime standard ci-dessous. Voir l'historique git.

---

## 1. Anneau

```
R    = ℤ[X] / (X² − X − 1)          anneau entier ; X joue le rôle de φ (φ² = φ + 1)
R_q  = 𝔽_q[X] / (X² − X − 1)        sa réduction modulo q
q    = 28657 = F₂₃                  nombre premier de Fibonacci
```

**Fait 1.** `q ≡ 2 (mod 5)`. Le discriminant de `X² − X − 1` vaut 5, qui n'est
pas un carré modulo `q` (critère d'Euler). Le polynôme est irréductible sur
`𝔽_q`, et `R_q ≅ 𝔽_{q²}` est un corps.

**Représentation.** `a = a₀ + a₁X` est représenté par `(a₀, a₁)`. Comme
`X² = X + 1`, la multiplication par `a` agit sur `(b₀, b₁)` par :

```
M(a) = [ a₀    a₁    ]          M(X) = [ 0  1 ]   (matrice de Fibonacci)
       [ a₁  a₀ + a₁ ]                 [ 1  1 ]
```

Les coefficients modulo `q` sont représentés de façon centrée, dans `(−q/2, q/2]`.
La norme utilisée est la norme `ℓ∞` sur les coefficients entiers.

## 2. Paramètres

| Symbole | Valeur | Sens |
|---|---|---|
| `k` | 704 | dimension sur `R_q` |
| `n̂ = 2k` | 1408 | dimension entière (lois de conservation) |
| `q` | 28657 = F₂₃ | module |

## 3. Clés

```
graine ←$ {0,1}^256 ;   A = Expand(graine) ∈ R_q^(k × k)
s, e ←$ {−1, 0, 1}^n̂                    coordonnées uniformes et indépendantes
y = A·s + e  (mod q)                    clé publique : (graine, y)
```

Forme « stœchiométrique » équivalente : `Â = [A | I]`, `x = (s, e)`, `Â·x = y`.
La matrice identité représente les espèces « libres » de la réaction. C'est
la forme de la clé publique de ML-DSA (`t = A s₁ + s₂`).

**Hypothèse H1.** `Expand` (SHAKE256, échantillonnage par rejet) produit une
matrice indistinguable d'une matrice uniforme. C'est une hypothèse de
pseudo-aléa ; l'usage identique dans ML-DSA est un précédent, pas une garantie
transférée.

## 4. Ce qui est démontré (pour A uniforme)

**Fait 2 — Unicité de la clé.** Soit `z = (z₁, z₂) ≠ 0` avec `|z_i| < q`. Si
`z₁ ≠ 0`, `A z₁` est uniforme sur `R_q^k` (`R_q` est un corps), donc
`Pr[Â z = 0] = q^(−n̂)`. Si `z₁ = 0`, `Â z = z₂ ≠ 0`. Par union sur les
`3^(2n̂) − 1` autres vecteurs ternaires :

```
E[nombre d'autres clés secrètes ternaires donnant y] ≤ 3^2816 · q^(−1408) ≈ 2^(−16384)
```

**Fait 3 — Absence de collisions courtes.** Par le même argument sur les
`5^(2n̂)` vecteurs `z ∈ {−2, …, 2}^(2n̂)` :

```
Pr[∃ z ≠ 0, ‖z‖∞ ≤ 2, Â z = 0] ≤ 5^2816 · q^(−1408) ≈ 2^(−14309)
```

Deux clés secrètes distinctes ne peuvent donc pas avoir la même clé publique,
sauf avec une probabilité négligeable sur `A`. Ce résultat est **statistique** :
il ne dépend d'aucune hypothèse de calcul.

**Fait 4 — Récupération de clé = LWE.** Retrouver `(s, e)` à partir de
`(A, y)` est exactement une instance de LWE `y = A s + e` sous forme normale :
secret et erreur ternaires, `n̂ = 1408` échantillons pour un secret de
dimension 1408. C'est le régime standard (autant d'échantillons que de
dimensions), pas un régime sous-déterminé.

Ces faits portent sur `A` uniforme et indépendante du secret. Ils ne prouvent
rien pour une matrice concrète donnée par une graine.

## 5. Estimations

**Outil** : lattice estimator, commit `e4333d9bf9ef42fd8a29651b0c559fba7ce0d834`,
SageMath 10.8.13 (passagemath). Appels exacts : `research/eqsd_estimate.py`.
La structure de degré 2 est ignorée : le réseau est supposé se comporter comme
un réseau aléatoire face à BKZ, convention identique à celle des estimations
publiées de ML-KEM.

**Récupération de clé, comparée à ML-KEM-1024 avec le même outil :**

Coût de la **meilleure** attaque dans chaque modèle :

| Modèle | EqSD-1408 | ML-KEM-1024 |
|---|---|---|
| `rough` (core-SVP) | ≈ 2²⁶³ (dual hybride, β = 899) | ≈ 2²⁴² (dual hybride, β = 826) |
| complet (défaut) | ≈ 2²⁸³ (dual hybride, β = 897) | ≈ 2²⁶² (dual hybride, β = 823) |

Les tailles de bloc (≈ 900) sont proches de celles de ML-KEM-1024 : on reste
dans la zone où l'outil est habituellement utilisé, pas en extrapolation.

**Affirmation retenue (comparative).** Selon cet estimateur et ces modèles,
retrouver une clé EqSD-1408 est au moins aussi coûteux que retrouver une clé
ML-KEM-1024. Ce n'est pas un niveau de sécurité absolu : c'est un classement
relatif dans un modèle heuristique commun.

**Attaques exclues :** Arora–Ge et BKW, qui exigent beaucoup plus
d'échantillons que les `n̂` publiés. À confirmer par un calcul explicite.

**Collisions :** inutile d'estimer SIS, le Fait 3 les exclut statistiquement.

## 6. Ce qui reste ouvert

1. **Réduction pire cas pour LWE à erreur ternaire.** Les réductions
   classiques supposent une erreur gaussienne. Pour une erreur uniforme petite
   et un nombre d'échantillons limité, il existe des résultats (Micciancio–
   Peikert, CRYPTO 2013). Il reste à vérifier que `m = n̂` et `q = 28657`
   satisfont leurs hypothèses exactes.
2. **Structure dorée.** Aucune preuve que la structure de degré 2 n'ouvre pas
   d'attaque. Aucune n'est connue ; c'est un constat, pas une preuve.
3. **Hypothèse H1.**
4. **Coût de la structure.** Avec un anneau de degré 2, `A` contient
   `704² ≈ 496 000` éléments, contre 16 polynômes pour ML-KEM. Générer et
   multiplier `A` est donc beaucoup plus lourd. Piste : un anneau de plus
   grand degré qui garde φ, par exemple `ℤ[φ][Y]/(Y^d + 1)`.
5. **Signature.** À construire ensuite ; ses bornes plus larges demanderont
   une nouvelle estimation.

## 7. Tailles

| Objet | Taille |
|---|---|
| `y` (15 bits par coefficient) | 1408 × 15 = 21120 bits = 2640 octets |
| Graine de `A` | 32 octets |
| **Clé publique** | **2672 octets** |
| Clé secrète, stockée comme graine | 32 octets |
| Clé secrète développée, codage 2 bits | 704 octets |
