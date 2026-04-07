# Contribution à CTF Buddy

[English](CONTRIBUTING.md) | Français

Merci pour votre contribution.

CTF Buddy est actuellement centré sur des workflows CTF orientés réseau. Les contributions sont particulièrement utiles lorsqu'elles améliorent :
- l'analyse de captures réseau
- l'extraction de protocoles d'authentification
- les helpers de décodage et de cassage liés aux challenges réseau
- la documentation, les tests et l'ergonomie autour de ce workflow

## Démarrage

1. Clonez le dépôt.
2. Créez un environnement virtuel.
3. Installez les dépendances depuis `CTF_buddy/requirements.txt`.
4. Lancez la CLI depuis la racine du dépôt avec `python main.py --help`.

Exemple :

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r CTF_buddy/requirements.txt
python main.py --help
```

## Règles de contribution

- Gardez le projet network-first pour le moment.
- Préférez les pull requests petites et ciblées.
- Ne commitez pas de secrets, de clés API, de grosses wordlists, ni de captures déjà résolues.
- Ajoutez ou mettez à jour les tests si vous modifiez la logique d'analyse, de décodage, de validation ou de classification.
- Étendez de préférence les workflows existants avant d'ajouter trop de nouveaux concepts de haut niveau.

## Ajouter une nouvelle capacité

Si vous ajoutez un nouveau helper :

1. Implémentez le comportement dans `CTF_buddy/tools/network.py` ou `CTF_buddy/tools/crypto.py`.
2. Enregistrez l'outil dans `CTF_buddy/tools/registry.py`.
3. Mettez à jour `pcap_inspect()` si la fonctionnalité est pilotée par une capture réseau.
4. Mettez à jour `CTF_buddy/mindmap.py` pour que la classification puisse orienter le bon workflow.
5. Ajoutez un test ou une vérification à base de fixture quand c'est possible.
6. Mettez à jour le README si le périmètre pris en charge évolue.

## Pull requests

Une bonne pull request contient généralement :
- un résumé court du problème
- l'approche choisie
- les limites ou compromis éventuels
- les tests ajoutés ou les vérifications manuelles effectuées

Si votre changement touche des outils externes comme `hashcat`, `tshark` ou `dig`, précisez ce que vous avez testé localement et ce qu'il reste à vérifier.

## Note sur le périmètre

Les idées pour un support CTF plus général sont bienvenues, mais essayez de garder l'implémentation alignée avec la direction actuelle du projet :

`CTF Buddy est d'abord un assistant pour les challenges réseau, puis un futur copilote CTF plus large.`
