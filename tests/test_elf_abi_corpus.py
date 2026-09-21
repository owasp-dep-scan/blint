"""Corpus tests for the ELF ABI analysis, run against real distribution images.

The checked-in fixtures are all produced by one toolchain, which is enough to
test the code paths and not enough to test the assumptions. Real distributions
disagree in exactly the places this analysis reasons about: version node naming
(``LIBPAM_EXTENSION_1.0`` and ``NCURSES6_TINFO_5.7.20081102`` both broke an
earlier version of the node grammar), library directory layout, whether symbol
versioning is used at all, and which C library is in play.

Each image is analysed in place and every result is checked against ground truth
read out of ``readelf`` in the same container, so the tests assert against the
linker's own view rather than against values recorded from a previous run.

The images span the packaging families that matter:

- Debian and Ubuntu, which use the multiarch ``/usr/lib/<triplet>`` layout
- Red Hat (UBI), which uses a flat ``/usr/lib64`` layout and an older glibc
- openSUSE Tumbleweed, which tracks a much newer glibc
- Alpine, which is musl and therefore has no symbol versioning at all

Each image is pulled and blint is installed into it, so a full run takes several
minutes and depends on the network and on registry availability. That is the
wrong shape for a check gating every pull request, so these are opt-in: set
``BLINT_CORPUS_TESTS=1``. They also skip when Docker is absent or its daemon
cannot run Linux containers.

An image is analysed on first use rather than up front, and an image that
cannot be prepared -- an unreachable registry, a mirror that drops a package --
skips the tests that need it and names the failing command, instead of erroring
every test in the file with an empty log.

Run them with:

    BLINT_CORPUS_TESTS=1 pytest tests/test_elf_abi_corpus.py -v

Select one distribution with:

    BLINT_CORPUS_TESTS=1 pytest tests/test_elf_abi_corpus.py -k alpine -v

The `corpus` workflow runs them on a schedule and on demand.
"""

import json
import os
import shutil
import subprocess

import pytest

# These tests pull five container images and install blint into each, so they
# take minutes and depend on the network and on registry availability. That is
# the wrong shape for a check that gates every pull request, but the right shape
# for periodic validation, so they are opt-in.
CORPUS_ENABLED = os.getenv("BLINT_CORPUS_TESTS", "").lower() in ("1", "true", "yes")


class Distro:
    """One container image and the command that prepares it for the probe."""

    def __init__(self, name, image, setup, python="python3", libc="glibc", versioned=True):
        self.name = name
        self.image = image
        self.setup = setup
        self.python = python
        # The C library the analysis is expected to report for this image.
        self.libc = libc
        # musl does not implement symbol versioning, so an image built on it has
        # no version nodes to find and the floor checks have nothing to compare.
        self.versioned = versioned

    def __repr__(self):
        return self.name


DISTROS = [
    Distro(
        "debian",
        "python:3.12-slim",
        "apt-get update -qq && apt-get install -y -qq binutils",
    ),
    Distro(
        "ubuntu",
        "ubuntu:24.04",
        "apt-get update -qq && apt-get install -y -qq python3 python3-pip binutils",
    ),
    Distro(
        "redhat",
        "registry.access.redhat.com/ubi9/ubi:latest",
        # UBI 9 ships Python 3.9 as python3; blint needs 3.10 or newer.
        "dnf install -y -q python3.12 python3.12-pip binutils",
        python="python3.12",
    ),
    Distro(
        "opensuse",
        # Pinned by digest because Tumbleweed is a rolling release: `latest`
        # renames its Python package on its own schedule, and the setup command
        # below names `python313` explicitly. Bump this deliberately, together
        # with that package name, so the newer glibc this image is here for
        # arrives as a reviewed change rather than as a Monday cron failure.
        "opensuse/tumbleweed@sha256:"
        "1dafc5a642242268bcd8f7e4f7e7d2531b73fd724328497e5ec97492b1c31914",
        "zypper -n -q install python313 python313-pip binutils",
        python="python3.13",
    ),
    Distro(
        "alpine",
        "alpine:3.21",
        "apk add --no-cache python3 py3-pip binutils",
        libc="musl",
        versioned=False,
    ),
]


def linux_docker_available() -> bool:
    """Return True when Docker is present and can run Linux containers.

    Checking that the daemon responds is not enough. Windows runners have a
    working Docker whose daemon is in Windows-container mode, where pulling any
    of these images fails with "no matching manifest for linux/amd64".
    """
    if not shutil.which("docker"):
        return False
    try:
        completed = subprocess.run(
            ["docker", "info", "--format", "{{.OSType}}"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0 and completed.stdout.strip() == "linux"


pytestmark = [
    pytest.mark.skipif(
        not CORPUS_ENABLED,
        reason="set BLINT_CORPUS_TESTS=1 to run the container corpus tests",
    ),
    pytest.mark.skipif(
        not linux_docker_available(),
        reason="Docker with a Linux daemon is required for the corpus tests",
    ),
]


# Printed by the container when the image could not be prepared: the package
# manager failed, or the interpreter or blint it was supposed to install is not
# there. That is the registry or a mirror failing, not a result about blint, so
# the tests say so rather than reporting a probe that never ran as a defect.
PREP_FAILED = "BLINT_PREP_FAILED"

# Both logs are kept in full inside the container and only their tails are
# printed, because an apt or zypper transcript is thousands of lines of package
# names and the failure is always at the end.
LOG_TAIL_LINES = 100


class ProbeUnavailable(Exception):
    """The image could not be prepared, so no probe result exists to check."""


def run_probe(distro: Distro, repo_root: str) -> dict:
    """Install blint in the image and run the probe, returning its report.

    Raises ``ProbeUnavailable`` when the image could not be prepared at all.
    """
    # Preparation output is kept rather than discarded. It used to go to
    # /dev/null, which made a failed package install and a broken probe produce
    # the same empty output, and a Tumbleweed mirror failure then read as
    # "probe produced no result" with nothing to act on.
    command = (
        f"{{ {distro.setup} ; }} >/tmp/prep.log 2>&1; "
        # The checkout is bind-mounted, and an editable install writes build
        # metadata back into it. With several images installing in sequence
        # against the same mount they corrupt each other's state, so each
        # container builds from its own copy.
        "cp -r /blint /tmp/blint-src >>/tmp/prep.log 2>&1; "
        # --break-system-packages is needed on the images that mark their system
        # Python as externally managed, and is rejected by older pip, so the
        # plain form is the fallback.
        f"({distro.python} -m pip install --break-system-packages -q -e /tmp/blint-src "
        f"|| {distro.python} -m pip install -q -e /tmp/blint-src) >>/tmp/prep.log 2>&1; "
        # Asked of the interpreter rather than inferred from pip's exit status,
        # so a pip that reports success without installing anything is caught
        # here instead of surfacing as an empty probe.
        f'if ! {distro.python} -c "import blint" >>/tmp/prep.log 2>&1; then '
        f'echo "{PREP_FAILED}" >&2; tail -n {LOG_TAIL_LINES} /tmp/prep.log >&2; exit 0; fi; '
        f"{distro.python} /tmp/blint-src/tests/data/elf_corpus_probe.py 2>/tmp/probe.log; "
        f"tail -n {LOG_TAIL_LINES} /tmp/probe.log >&2"
    )
    completed = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "-v",
            # Read-only: nothing in the container should write to the checkout.
            f"{repo_root}:/blint:ro",
            "-w",
            "/tmp",
            distro.image,
            "sh",
            "-c",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=3600,
    )
    detail = (
        f"exit status {completed.returncode}\n"
        f"stdout:\n{completed.stdout[-4000:]}\n"
        f"stderr:\n{completed.stderr[-4000:]}"
    )
    if PREP_FAILED in completed.stderr:
        raise ProbeUnavailable(f"[{distro.name}] could not prepare {distro.image}.\n{detail}")
    if completed.returncode != 0 and "BLINT_RESULT_START" not in completed.stdout:
        # docker itself failed -- the pull did not complete, or the daemon
        # killed the container. The shell above exits 0 on every path it
        # controls, so a non-zero status with no result did not come from blint.
        raise ProbeUnavailable(f"[{distro.name}] could not run {distro.image}.\n{detail}")
    if "BLINT_RESULT_START" not in completed.stdout:
        pytest.fail(f"[{distro.name}] probe produced no result.\n{detail}")
    payload = completed.stdout.split("BLINT_RESULT_START", 1)[1].strip()
    return json.loads(payload.splitlines()[0])


class CorpusReports:
    """The probe reports, produced on first use and cached for the session.

    Each image is analysed at most once, and lazily. The reports used to be
    built eagerly in one comprehension, which meant one unreachable registry
    turned every test in the file into an error about that image -- fifty-three
    of them, none of them about the distribution they were named after.
    """

    def __init__(self, repo_root: str):
        self._repo_root = repo_root
        self._reports: dict[str, dict] = {}
        self._unavailable: dict[str, str] = {}

    def _fetch(self, distro: Distro) -> dict:
        """Return this image's report, raising ``ProbeUnavailable`` if it has none."""
        if distro.name in self._unavailable:
            raise ProbeUnavailable(self._unavailable[distro.name])
        if distro.name not in self._reports:
            try:
                self._reports[distro.name] = run_probe(distro, self._repo_root)
            except ProbeUnavailable as exc:
                self._unavailable[distro.name] = str(exc)
                raise
        return self._reports[distro.name]

    def report(self, distro: Distro) -> dict:
        """Return this image's report, skipping the test if it is unreachable."""
        try:
            return self._fetch(distro)
        except ProbeUnavailable as exc:
            pytest.skip(str(exc))

    def reachable(self) -> dict[str, dict]:
        """Return a report per image that could be prepared.

        Used by the assertions made across the whole corpus rather than per
        image. An unreachable registry narrows what they run against, so they
        say which images are missing; losing them all leaves nothing to assert
        and is a skip rather than a pass.
        """
        available, missing = {}, []
        for distro in DISTROS:
            if distro.name in self._unavailable:
                missing.append(distro.name)
                continue
            try:
                available[distro.name] = self._fetch(distro)
            except ProbeUnavailable:
                missing.append(distro.name)
        if not available:
            pytest.skip(f"no image could be prepared: {', '.join(missing)}")
        if missing:
            # Loud on purpose: the corpus-wide assertions below are weaker than
            # they look when an image is missing, and a quiet pass would hide
            # that.
            print(f"corpus narrowed -- these images could not be prepared: {', '.join(missing)}")
        return available


@pytest.fixture(scope="session")
def corpus(request) -> CorpusReports:
    """Analyse each image once and cache the reports for the whole session."""
    return CorpusReports(str(request.config.rootpath))


@pytest.fixture
def corpus_reports(corpus) -> dict[str, dict]:
    """Every report the registry allowed us to collect, keyed by image name."""
    return corpus.reachable()


@pytest.fixture(params=DISTROS, ids=lambda distro: distro.name)
def distro_report(request, corpus):
    distro = request.param
    return distro, corpus.report(distro)


def test_objects_were_found_and_parsed(distro_report):
    distro, report = distro_report
    # A distribution with almost nothing to analyse would make every other
    # assertion here vacuously true.
    assert report["objects"] >= 20, f"{distro.name}: only {report['objects']} objects found"
    assert report["parse_failures"] == [], f"{distro.name}: {report['parse_failures'][:3]}"
    assert report["parsed"] == report["objects"]


def test_abi_requirements_match_readelf(distro_report):
    distro, report = distro_report
    # Checked per provider, not just glibc, so a node from libstdc++, PAM or
    # ncurses is validated on the same footing.
    assert report["floor_mismatched"] == [], f"{distro.name}: {report['floor_mismatched'][:3]}"
    assert report["floor_matched"] >= 20


def test_dynamic_dependencies_match_readelf(distro_report):
    distro, report = distro_report
    assert report["needed_mismatched"] == [], f"{distro.name}: {report['needed_mismatched'][:3]}"
    assert report["needed_matched"] >= 20


def test_every_version_node_parses(distro_report):
    distro, report = distro_report
    # Any provider here is a node whose version the grammar failed to split off.
    assert report["unparsed_nodes"] == {}, f"{distro.name}: {report['unparsed_nodes']}"


def test_symbol_names_are_never_lost(distro_report):
    distro, report = distro_report
    # An object whose symbols all parse to empty names drops out of every
    # symbol-derived result without any error being raised.
    assert report["nameless_symbol_objects"] == [], (
        f"{distro.name}: {report['nameless_symbol_objects'][:5]}"
    )


def test_c_library_is_identified(distro_report):
    distro, report = distro_report
    counts = report["libc_counts"]
    assert counts.get(distro.libc, 0) > 0, f"{distro.name}: identified {counts}"
    # The expected libc must dominate. A handful of objects reporting unknown is
    # normal; a majority doing so means the detection is not working here.
    assert counts[distro.libc] >= max(counts.values()) / 2


def test_symbol_versioning_matches_the_platform(distro_report):
    distro, report = distro_report
    if distro.versioned:
        # Every glibc distribution has objects binding GLIBC_PRIVATE.
        assert report["private_nodes"] > 0, f"{distro.name}: no private version nodes found"
    else:
        # musl implements no symbol versioning, so finding version nodes here
        # would mean the analysis is inventing them.
        assert report["private_nodes"] == 0
        assert report["unparsed_nodes"] == {}


def test_unused_dependency_findings_are_true(distro_report):
    distro, report = distro_report
    # Verified with nm: a library reported unused must export none of the
    # symbols the binary leaves undefined. This is the finding's definition, so
    # a violation is a false positive rather than a difference of opinion.
    assert report["false_unused"] == [], f"{distro.name}: {report['false_unused'][:5]}"


def test_no_unused_dependency_is_missed(distro_report):
    distro, report = distro_report
    # `ldd -u` counts transitive use as use, so it can call a library used that
    # this binary never calls directly. It can never do the reverse, which makes
    # anything it reports unused a finding blint must also produce.
    assert report["missed_unused"] == [], f"{distro.name}: {report['missed_unused'][:5]}"


def test_attributed_symbols_are_really_exported(distro_report):
    distro, report = distro_report
    # Attributing a symbol to a library that does not export it is worse than
    # leaving it unattributed, because the wrong edge is indistinguishable from
    # a right one downstream.
    assert report["misattributed_symbols"] == [], (
        f"{distro.name}: {report['misattributed_symbols'][:5]}"
    )


def test_over_linking_is_detected_where_it_exists(corpus_reports):
    # Distributions that link with `--as-needed` are largely free of unused
    # dependencies, while those that do not are full of them. Finding none
    # anywhere would mean the check never fires.
    total = sum(report["unused_dependency_objects"] for report in corpus_reports.values())
    assert total > 0, "no unused dependency found in any image"


def test_runtime_loaded_dependencies_are_recovered(corpus_reports):
    # Libraries opened on demand never appear in DT_NEEDED, so recovering them
    # is the whole point of the pass. Recovery depends on the binary storing a
    # literal soname, which not every distribution's build does, so this is
    # asserted across the corpus rather than per image.
    recovered = {
        name
        for report in corpus_reports.values()
        for names in report["recovered"].values()
        for name in names
    }
    assert recovered, f"nothing recovered across {list(corpus_reports)}"


def test_abi_features_are_detected_somewhere(corpus_reports):
    # Indirect functions and thread local storage are rare per object but always
    # present somewhere in a full distribution. Zero across every image would
    # mean the detection is broken rather than that the corpus is clean.
    assert sum(report["ifunc"] for report in corpus_reports.values()) > 0
    assert sum(report["tls"] for report in corpus_reports.values()) > 0
    assert sum(report["implementation_specific"] for report in corpus_reports.values()) > 0
