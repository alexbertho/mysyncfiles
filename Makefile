.DEFAULT_GOAL := help

COMPOSE_SERVER = docker compose --env-file deploy/.env -f deploy/compose.yaml
COMPOSE_DOCS = docker compose --env-file deploy/.env.example -f deploy/compose.yaml --profile docs
MYSYNC_DOCS_DIR ?= /var/www/mysyncfiles/docs

.PHONY: help check-config install start stop logs pair test deploy clean docs docs-stop docs-check docs-build

help:
	@printf '%s\n' \
		'make install     Vérifier deploy/.env et construire le serveur' \
		'make start       Démarrer le serveur' \
		'make stop        Arrêter le serveur sans supprimer les données' \
		'make logs        Suivre les journaux du serveur' \
		'make pair        Appairer un client par son code temporaire' \
		'make test        Vérifier le code, l’installateur et la documentation' \
		'make deploy      Tester, reconstruire et déployer le serveur et la documentation' \
		'make clean       Supprimer target/ et site/ (sans toucher aux données)' \
		'make docs        Voir la documentation sur http://127.0.0.1:8000' \
		'make docs-stop   Arrêter la prévisualisation' \
		'make docs-check  Construire et vérifier la documentation' \
		'make docs-build  Générer site/ avec l’origine HTTPS configurée'

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

test:
	sh -n deploy/install.sh
	cargo fmt --all -- --check
	@if pkg-config --atleast-version=2.4.6 tss2-sys; then \
		cargo test --locked; \
	else \
		printf '%s\n' 'Bibliothèques TPM absentes ou trop anciennes : tests Rust dans le conteneur de développement.'; \
		install -d "$$HOME/.cargo/registry" && \
		docker build -t mysyncfiles-tpm-dev -f deploy/Dockerfile.tpm-dev . && \
		docker run --rm --user "$$(id -u):$$(id -g)" \
			--volume "$$(pwd):/src" \
			--volume "$$HOME/.cargo/registry:/tmp/cargo/registry" \
			--env CARGO_HOME=/tmp/cargo mysyncfiles-tpm-dev cargo test --locked; \
	fi
	python3 -B -m unittest discover -s tests -p 'test_*.py'
	$(MAKE) docs-check

deploy:
	$(MAKE) test
	$(MAKE) check-config
	@command -v rsync >/dev/null && command -v sudo >/dev/null && test "$(MYSYNC_DOCS_DIR)" != / && sudo -v
	$(COMPOSE_SERVER) build server
	$(MAKE) docs-build
	$(COMPOSE_SERVER) up -d --no-build server
	sudo install -d -m 0755 "$(MYSYNC_DOCS_DIR)"
	sudo rsync -a --delete site/ "$(MYSYNC_DOCS_DIR)/"

clean:
	cargo clean
	rm -rf site

docs:
	$(COMPOSE_DOCS) up -d --build docs

docs-stop:
	$(COMPOSE_DOCS) stop docs

docs-check:
	$(COMPOSE_DOCS) run --rm --build docs build --strict

docs-build: check-config
	@public_url=$$($(COMPOSE_SERVER) run --rm --no-deps server device public-url --data-dir /data) || exit; \
	case "$$public_url" in https://*) ;; *) printf '%s\n' 'L’origine publique configurée doit utiliser HTTPS.' >&2; exit 1;; esac; \
	install -d -m 0755 site; \
	MYSYNC_PUBLIC_URL="$$public_url" MYSYNC_DOCS_SITE_URL="$$public_url/docs/" \
		$(COMPOSE_DOCS) run --rm --build --user "$$(id -u):$$(id -g)" \
		--volume "$$(pwd)/site:/workspace/site" \
		--env MYSYNC_PUBLIC_URL --env MYSYNC_DOCS_SITE_URL docs build --strict
