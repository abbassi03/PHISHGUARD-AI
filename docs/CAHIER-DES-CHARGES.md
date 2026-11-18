# PHISHGUARD AI — Cahier des charges & architecture

**Version:** 1.0 — Initial design  
**Niveau cible:** Master 1 — Cybersécurité & Intelligence Artificielle  
**Type:** Projet académique + application démonstrative  
**Périmètre principal:** Détection de phishing à partir des caractéristiques lexicales et structurelles d'une URL, sans visiter le site cible.

---

## 1. Résumé du projet

PHISHGUARD AI est une application qui analyse une URL et estime si elle ressemble à une URL légitime ou à une URL de phishing. Le système extrait localement des caractéristiques de la chaîne URL, transmet ces caractéristiques à un modèle de classification entraîné, puis présente une prédiction, un niveau de risque indicatif et une explication des facteurs qui ont contribué à la décision.

Le projet comprend deux volets complémentaires :

1. **Volet scientifique :** préparation des données, feature engineering, comparaison de plusieurs modèles, évaluation rigoureuse et analyse des erreurs.
2. **Volet applicatif :** interface web, analyse d'une URL, analyse par lot, visualisations, explications et export de rapports.

Le système est un outil d'aide à l'analyse. Il ne garantit pas qu'un site est sûr et ne remplace ni une passerelle de sécurité ni une investigation humaine.

## 2. Problématique

Les URL de phishing peuvent imiter des noms de marques, contenir des sous-domaines trompeurs, utiliser des caractères inhabituels ou masquer la destination réelle. Une inspection visuelle seule peut être insuffisante.

**Problématique de recherche :** dans quelle mesure les caractéristiques lexicales et structurelles d'une URL, extraites sans ouvrir la page web, permettent-elles de distinguer les URL de phishing des URL légitimes ?

### Questions de recherche

- QR1 — Quelles caractéristiques d'une URL apportent le plus d'information pour distinguer les deux classes ?
- QR2 — Quel modèle classique de Machine Learning fournit le meilleur compromis entre précision, rappel et taux de faux positifs ?
- QR3 — Les résultats restent-ils cohérents lorsque les domaines sont séparés entre les ensembles d'entraînement et de test ?
- QR4 — Comment expliquer une prédiction à l'aide de l'importance des caractéristiques et, si pertinent, de SHAP ?

## 3. Objectifs

### Objectifs fonctionnels

- Permettre la saisie et l'analyse d'une URL.
- Valider le format de l'URL sans effectuer de requête réseau vers le site cible.
- Extraire un vecteur de caractéristiques URL-only.
- Retourner une classe prédite et un score du modèle clairement présenté comme une estimation.
- Expliquer les caractéristiques les plus influentes.
- Analyser un fichier CSV d'URL par lot.
- Afficher l'historique local des analyses et exporter les résultats.
- Présenter les statistiques du jeu de données et les résultats des expériences ML.

### Objectifs scientifiques

- Documenter le jeu de données et la provenance des labels.
- Éviter la fuite de données (*data leakage*), notamment entre URL d'un même domaine.
- Comparer plusieurs modèles avec un protocole reproductible.
- Analyser les faux positifs et les faux négatifs.
- Documenter les limites de généralisation et les biais possibles du dataset.

## 4. Périmètre et limites

### Inclus dans la version 1

- Analyse basée uniquement sur la chaîne URL et ses composants syntaxiques.
- Classification binaire : `phishing` / `legitimate`.
- Modèles classiques supervisés.
- Interface locale de démonstration.
- Analyse CSV en lot.
- Explications globales et locales lorsque la méthode est compatible avec le modèle.

### Exclus de la version 1

- Ouverture, navigation ou rendu du site analysé.
- Exécution de JavaScript, téléchargement de fichiers ou interaction avec le site.
- Analyse du contenu HTML, des captures d'écran ou du certificat TLS.
- WHOIS, DNS, réputation externe ou requêtes à des services tiers.
- Blocage automatique d'un site ou d'une URL.

Ces fonctionnalités peuvent être étudiées plus tard dans un périmètre séparé, avec des contrôles de sécurité appropriés.

## 5. Jeu de données

### Source principale proposée

**PhiUSIIL Phishing URL (Website) — UCI Machine Learning Repository**  
https://archive.ics.uci.edu/dataset/967/phiusil+phishing+url+dataset

La fiche UCI indique :

- 235 795 instances ;
- 54 caractéristiques ;
- 134 850 URL légitimes ;
- 100 945 URL de phishing ;
- `label = 1` pour une URL légitime et `label = 0` pour une URL de phishing ;
- licence CC BY 4.0.

**Attention méthodologique :** la fiche UCI précise que les caractéristiques proviennent à la fois de l'URL et du code source de la page web. Pour respecter le périmètre URL-only, le pipeline ne doit pas utiliser aveuglément toutes les colonnes pré-calculées. Il doit partir de la colonne URL et du label, puis recalculer localement les caractéristiques autorisées à partir de la chaîne URL. Les caractéristiques qui nécessitent le HTML, le titre de page ou une autre donnée externe seront exclues de l'expérience principale.

Le rapport final doit citer la dataset et sa licence, et préciser les colonnes effectivement utilisées.

## 6. Pipeline de données et de Machine Learning

```text
Dataset CSV
   │
   ▼
Audit du schéma, des labels et des doublons
   │
   ▼
Sélection des colonnes URL + label uniquement
   │
   ▼
Normalisation sûre de la chaîne URL
   │
   ▼
Extraction de caractéristiques URL-only
   │
   ▼
Contrôles qualité + analyse exploratoire
   │
   ▼
Séparation train / validation / test par domaine
   │
   ▼
Prétraitement appris uniquement sur train
   │
   ▼
Entraînement et comparaison des modèles
   │
   ▼
Évaluation, calibration et analyse des erreurs
   │
   ▼
Sauvegarde du pipeline complet + métadonnées
   │
   ▼
Application : URL Analyzer / Batch Analysis / Reports
```

### Règles de préparation

- Vérifier les colonnes requises, les types, les valeurs de labels et les URL vides ou mal formées.
- Supprimer ou documenter les doublons exacts avant le découpage.
- Ne jamais utiliser `FILENAME`, un identifiant, ni une caractéristique issue du HTML dans le modèle URL-only.
- Calculer le même ensemble ordonné de caractéristiques pendant l'entraînement et pendant l'inférence.
- Enregistrer la version du dataset, la graine aléatoire, les paramètres et le schéma des caractéristiques.
- Effectuer tout encodage, imputation, sélection ou mise à l'échelle à l'intérieur d'un `Pipeline`/`ColumnTransformer` ajusté uniquement sur les données d'entraînement.

## 7. Conception des caractéristiques

Les caractéristiques finales seront figées après inspection des URL et tests unitaires. La liste initiale proposée :

| Feature | Description |
|---|---|
| `url_length` | Longueur totale de l'URL |
| `hostname_length` | Longueur du nom d'hôte |
| `path_length` | Longueur du chemin |
| `query_length` | Longueur de la chaîne de requête |
| `num_dots` | Nombre de points |
| `num_hyphens` | Nombre de tirets |
| `num_underscores` | Nombre de tirets bas |
| `num_digits` | Nombre de chiffres |
| `num_at_symbols` | Nombre de caractères `@` |
| `num_subdomains` | Nombre estimé de sous-domaines |
| `has_ip_host` | Hôte sous forme d'adresse IP |
| `uses_https_scheme` | Schéma HTTPS déclaré dans l'URL |
| `has_nonstandard_port` | Présence d'un port explicite non standard |
| `num_percent_encodings` | Nombre d'encodages `%xx` |
| `num_suspicious_tokens` | Nombre de termes suspects selon une liste documentée |
| `url_entropy` | Mesure de diversité des caractères |
| `has_fragment` | Présence d'un fragment `#` |
| `num_query_parameters` | Nombre de paramètres de requête |

**Précautions :** HTTPS n'est pas une preuve de légitimité ; une URL longue ou contenant des mots sensibles n'est pas automatiquement malveillante. Les caractéristiques sont des signaux statistiques, pas des règles absolues. L'estimation du nombre de sous-domaines dépendra d'une bibliothèque de suffixes publics/versionnée ; sinon la méthode simplifiée sera explicitement documentée.

## 8. Protocole expérimental

### Modèles de départ

1. DummyClassifier — baseline minimale.
2. Logistic Regression — baseline interprétable.
3. Decision Tree — comparaison non linéaire simple.
4. Random Forest — modèle d'ensemble.
5. HistGradientBoosting ou Gradient Boosting — comparaison supplémentaire.
6. SVM — optionnel selon le coût de calcul après un premier benchmark.

Ne pas entraîner tous les modèles avec des paramètres coûteux avant d'avoir établi une baseline.

### Découpage des données

- Expérience de référence : split stratifié, clairement étiqueté comme référence et non comme preuve de généralisation.
- Expérience principale : séparation par domaine enregistré (*registered domain*) pour éviter qu'un même domaine apparaisse à la fois dans train et test.
- Garder un test final verrouillé jusqu'au choix des modèles et hyperparamètres.
- Rapporter le nombre de domaines et la distribution des classes dans chaque split.

### Métriques

- Precision, Recall, F1-score (par classe et macro).
- Confusion matrix.
- ROC-AUC et PR-AUC.
- False Positive Rate et False Negative Rate.
- Temps d'entraînement et temps moyen d'inférence.
- Calibration des probabilités, si des probabilités sont affichées.

Le seuil de décision ne doit pas être choisi sur le test final. Il est sélectionné sur validation selon un objectif documenté, par exemple limiter les faux négatifs tout en gardant un taux de faux positifs acceptable.

### Analyse d'erreurs

- Faux positifs : URL légitimes signalées comme phishing.
- Faux négatifs : URL de phishing classées comme légitimes.
- Examiner les erreurs par longueur, TLD, type de domaine et famille de caractéristiques, sans publier de données sensibles.

## 9. Explainable AI

### Niveau global

- Importance par permutation sur validation/test.
- Importance des arbres, présentée comme diagnostic et non comme preuve causale.
- SHAP en option si le modèle et le temps de calcul le permettent.

### Niveau local

Pour une URL analysée, présenter les caractéristiques qui ont le plus contribué au score du modèle, avec un libellé neutre : « facteurs associés à la prédiction ». Ne pas affirmer qu'un facteur isolé prouve une attaque.

## 10. Fonctionnalités de l'application

### Pages proposées

1. **Overview** — nombre d'analyses, répartition des classes prédites, tendances et version du modèle.
2. **URL Analyzer** — saisie d'une URL, validation locale, prédiction et explication.
3. **Batch Analysis** — import CSV, sélection de colonne URL, validation et export des résultats.
4. **Dataset Explorer** — distribution des classes, statistiques, histogrammes et corrélations des features.
5. **ML Laboratory** — comparaison des modèles, métriques, confusion matrices et courbes ROC/PR.
6. **Explainability** — importance globale et explication locale.
7. **Reports & History** — historique local et export CSV/HTML/PDF si la dépendance PDF est retenue.
8. **About & Methodology** — source du dataset, licence, méthodologie, limites et avertissement.

### Règles UI/UX

- Design cohérent : navy, blanc cassé, teal et accents violet ; couleurs de statut utilisées avec parcimonie.
- KPI cards basées sur des données réellement calculées.
- Graphiques avec titres, unités, légendes et états vides explicites.
- Tables filtrables et téléchargeables.
- Affichage des scores avec leur signification ; éviter de présenter une probabilité non calibrée comme une certitude.
- Interface responsive et navigation simple.

## 11. Architecture technique

**Stack proposée pour la V1 :**

- Python 3.12+ (version exacte verrouillée dans l'environnement du projet).
- Streamlit pour l'application web locale.
- Pandas / NumPy pour les données.
- Scikit-learn pour les pipelines et modèles.
- Plotly pour les visualisations.
- SHAP en option pour l'explicabilité.
- Joblib pour la sérialisation du pipeline final.
- Pytest pour les tests.

### Structure de dépôt proposée

```text
PHISHGUARD-AI/
├── app.py
├── pages/
│   ├── 1_URL_Analyzer.py
│   ├── 2_Batch_Analysis.py
│   ├── 3_Dataset_Explorer.py
│   ├── 4_ML_Laboratory.py
│   ├── 5_Explainability.py
│   └── 6_Reports.py
├── src/
│   └── phishguard/
│       ├── __init__.py
│       ├── config.py
│       ├── data/
│       │   ├── load.py
│       │   ├── validate.py
│       │   └── split.py
│       ├── features/
│       │   └── url_features.py
│       ├── modeling/
│       │   ├── pipeline.py
│       │   ├── train.py
│       │   ├── evaluate.py
│       │   └── predict.py
│       ├── explainability/
│       │   └── explain.py
│       └── reporting/
│           └── export.py
├── data/
│   ├── raw/                 # local only; ignored by Git
│   └── sample/              # tiny synthetic sample only
├── artifacts/               # trained models; policy-defined in Git
├── reports/
│   ├── figures/
│   └── metrics/
├── notebooks/
│   └── 01_eda.ipynb
├── tests/
│   ├── test_url_features.py
│   ├── test_data_pipeline.py
│   ├── test_model_pipeline.py
│   └── test_app_smoke.py
├── docs/
│   ├── CAHIER-DES-CHARGES.md
│   ├── ARCHITECTURE.md
│   ├── DATASET.md
│   └── EXPERIMENTS.md
├── .github/workflows/tests.yml
├── .gitignore
├── requirements.txt
├── requirements-dev.txt
├── README.md
└── LICENSE
```

## 12. Sécurité et confidentialité

- Ne pas visiter les URL saisies dans la V1 : aucune requête HTTP vers la cible.
- Ne pas rendre le HTML fourni par les utilisateurs.
- Valider les fichiers importés : taille maximale, extension, encodage, nombre de lignes et noms de colonnes.
- Limiter la taille des lots et éviter de charger des fichiers très volumineux entièrement en mémoire.
- Ne pas enregistrer de données personnelles inutiles dans l'historique.
- Ne jamais committer `.env`, fichiers contenant des secrets, données brutes privées ou fichiers temporaires.
- Afficher un avertissement : la prédiction est indicative et peut produire des faux positifs et faux négatifs.

## 13. Tests et critères d'acceptation

### Tests unitaires

- Extraction correcte des caractéristiques pour URL valides et cas limites.
- Rejet ou signalement des URL invalides sans crash.
- Même ordre et mêmes noms de features à l'entraînement et à l'inférence.
- Valeurs finies, types cohérents et absence de NaN inattendu.
- Vérification de l'encodage des labels : 0 = phishing, 1 = légitime dans la dataset UCI.

### Tests ML

- Le pipeline s'entraîne sur un petit jeu synthétique de test.
- Le modèle sauvegardé peut être rechargé et produire une prédiction.
- Le test final n'est pas utilisé pour le réglage du modèle ou du seuil.
- Le rapport contient toutes les métriques attendues.

### Tests applicatifs

- URL Analyzer accepte une URL valide et affiche une réponse.
- Batch Analysis valide le CSV et exporte une ligne par entrée traitée.
- L'interface affiche des erreurs compréhensibles.
- Les graphiques se basent sur les résultats chargés et non sur des nombres codés en dur.

### Critères de livraison

- Code modulaire, documenté et testé.
- Instructions d'installation et de lancement reproductibles.
- Source et licence du dataset citées.
- Résultats ML reproductibles avec graines et paramètres documentés.
- Limites du modèle clairement indiquées.
- Aucune promesse de détection parfaite.

## 14. Livrables

1. Application Streamlit fonctionnelle.
2. Pipeline de traitement et d'extraction URL-only.
3. Notebook EDA.
4. Scripts d'entraînement et d'évaluation.
5. Modèle sauvegardé accompagné de ses métadonnées.
6. Tableaux et graphiques expérimentaux.
7. Rapport méthodologique et fiche modèle (*Model Card*).
8. Tests automatisés.
9. README et dépôt GitHub documenté.

## 15. Plan de réalisation

| Phase | Résultat attendu |
|---|---|
| 0 — Cadrage | Cahier des charges validé |
| 1 — Dataset audit | Schéma, labels, licence et plan URL-only validés |
| 2 — Feature engineering | Extracteur testé et versionné |
| 3 — EDA | Notebook et graphiques reproductibles |
| 4 — Modélisation | Baselines, comparaison et évaluation par domaine |
| 5 — Explainability | Importance globale et explication locale |
| 6 — Application | Pages Streamlit et flux d'analyse |
| 7 — Validation | Tests, rapport, limitations et démo |
| 8 — Publication | GitHub, README, captures et instructions |

## 16. Références

- Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website) Dataset*. UCI Machine Learning Repository. https://archive.ics.uci.edu/dataset/967/phiusil+phishing+url+dataset
- DOI de l'article associé : https://doi.org/10.1016/j.cose.2023.103545

La fiche UCI indique une licence Creative Commons Attribution 4.0 International (CC BY 4.0). Les conditions et l'attribution doivent être conservées lors de la redistribution des données.
