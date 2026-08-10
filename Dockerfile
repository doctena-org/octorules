# syntax=docker/dockerfile:1

# Core is installed from this checkout (not PyPI) so release images never
# race the PyPI CDN; providers resolve to their latest published releases
# at build time. One image carries all providers so a single config can
# target any provider mix, including multi-provider files.
FROM python:3.14-slim AS build

COPY pyproject.toml README.md LICENSE /src/
COPY octorules/ /src/octorules/

RUN python -m venv /opt/octorules \
    && /opt/octorules/bin/pip install --no-cache-dir \
        /src \
        octorules-cloudflare \
        octorules-aws \
        octorules-azure \
        octorules-google \
        octorules-bunny \
    && /opt/octorules/bin/python -m compileall -q /opt/octorules/lib

FROM python:3.14-slim

# GitHub links the GHCR package to this repository via this label.
LABEL org.opencontainers.image.source="https://github.com/doctena-org/octorules"

COPY --from=build /opt/octorules /opt/octorules

ENV PATH="/opt/octorules/bin:$PATH" \
    PYTHONUNBUFFERED=1

# /octorules is the conventional mount point for the user's config directory.
RUN useradd --uid 1000 --create-home octorules \
    && mkdir -p /octorules \
    && chown octorules:octorules /octorules

USER octorules
WORKDIR /octorules

ENTRYPOINT ["octorules"]
CMD ["--help"]
