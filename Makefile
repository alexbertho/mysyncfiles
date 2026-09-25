.DEFAULT_GOAL := help

COMPOSE_SERVER = docker compose --env-file deploy/.env -f deploy/compose.yaml
COMPOSE_DOCS = docker compose --env-file deploy/.env.example -f deploy/compose.yaml --profile docs

.PHONY: help check-config install start stop logs pair docs docs-stop docs-check docs-build

help:
	@printf '%s\n' \
		'make install     Vérifier deploy/.env et construire le serveur' \
		'make start       Démarrer le serveur' \
		'make stop        Arrêter le serveur sans supprimer les données' \
		'make logs        Suivre les journaux du serveur' \
		'make pair        Appairer un client par son code temporaire' \
		'make docs        Voir la documentation sur http://127.0.0.1:8000' \
		'make docs-stop   Arrêter la prévisualisation' \
		'make docs-check  Construire et vérifier la documentation' \
		'make docs-build  Générer site/ pour une publication HTTPS'

check-config:
	@test -f deploy/.env || { printf '%s\n' "Copier deploy/.env.example vers deploy/.env et le configurer d'abord." >&2; exit 1; }
	$(COMPOSE_SERVER) config --quiet
	@for variable in MYSYNC_DATA_DIR MYSYNC_RELEASES_DIR; do \
		path=$$($(COMPOSE_SERVER) config --environment | sed -n "s/^$$variable=//p"); \
		case "$$path" in /*) ;; *) printf '%s doit être un chemin absolu.\n' "$$variable" >&2; exit 1;; esac; \
		test -d "$$path" || { printf '%s doit désigner un dossier existant.\n' "$$variable" >&2; exit 1; }; \
	done

install: check-config
	$(COMPOSE_SERVER) build server

start: check-config
	$(COMPOSE_SERVER) up -d server

stop:
	$(COMPOSE_SERVER) stop server

logs:
	$(COMPOSE_SERVER) logs -f server

pair: check-config
	$(COMPOSE_SERVER) run --rm server device pair --data-dir /data

docs:
	$(COMPOSE_DOCS) up -d --build docs

docs-stop:
	$(COMPOSE_DOCS) stop docs

docs-check:
	$(COMPOSE_DOCS) run --rm --build docs build --strict

docs-build:
	@case "$${MYSYNC_DOCS_SITE_URL:-}" in https://*/docs/) ;; *) printf '%s\n' 'Définir MYSYNC_DOCS_SITE_URL=https://sync.example.org/docs/ avant de construire le site.' >&2; exit 1;; esac
	@install -d -m 0755 site
	$(COMPOSE_DOCS) run --rm --build --user "$$(id -u):$$(id -g)" \
		--volume "$$(pwd)/site:/workspace/site" \
		--env MYSYNC_DOCS_SITE_URL docs build --strict
