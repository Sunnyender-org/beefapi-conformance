"""Local image-shaped workload; does not call an image provider or need a key."""

import base64
import hashlib
import sys
from pathlib import Path

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def install_image_skill(home: Path) -> None:
    skill = home / "skills" / "conformance-image"
    skill.mkdir(parents=True, exist_ok=True)
    (skill / "SKILL.md").write_text(
        "---\nname: conformance-image\ndescription: Generate the local conformance image fixture.\n---\n"
        "This is a deterministic test fixture, not a real image service.\n"
        f"Run `{sys.executable} {skill / 'generate.py'}` once in the workspace.\n"
        "Use exec_command with yield_time_ms=1000, then write_stdin on the returned session_id "
        "until completion. Do not restart the generator. Read back result.png, verify it is "
        "nonempty, then end with BEEFAPI_IMAGE_SKILL_OK in the final reply.\n",
        encoding="utf-8",
    )
    (skill / "generate.py").write_text(
        "import base64, time\nfrom pathlib import Path\n"
        "with Path('generation-count.txt').open('a') as f: f.write('1\\n')\n"
        "time.sleep(12)\n"
        f"Path('result.png').write_bytes(base64.b64decode({base64.b64encode(PNG).decode()!r}))\n"
        "print('Wrote result.png', flush=True)\n",
        encoding="utf-8",
    )


def image_skill_problems(workspace: Path) -> list[str]:
    problems = []
    image = workspace / "result.png"
    if (
        not image.is_file()
        or hashlib.sha256(image.read_bytes()).digest() != hashlib.sha256(PNG).digest()
    ):
        problems.append("image_fixture_pixels")
    count = workspace / "generation-count.txt"
    if not count.is_file() or count.read_text() != "1\n":
        problems.append("single_generation")
    return problems
