from honeypot.filesystem import VirtualFSError, VirtualFileSystem


def test_seed_tree_and_normalization() -> None:
    fs = VirtualFileSystem()
    assert fs.normalize("/root", "../etc/passwd") == "/etc/passwd"
    assert fs.normalize("/var/log", "~/scripts") == "/root/scripts"
    assert "root:x:0:0" in fs.read_file("/", "/etc/passwd")
    assert {entry.name for entry in fs.list_dir("/root")} >= {
        "backup",
        "docker-compose.yml",
        "scripts",
        "test.py",
    }


def test_mutations_remain_inside_one_virtual_instance() -> None:
    first = VirtualFileSystem()
    second = VirtualFileSystem()
    first.mkdir("/root", "/tmp/demo/nested", parents=True)
    first.write_file("/root", "/tmp/demo/nested/payload", "fake\n")
    assert first.read_file("/", "/tmp/demo/nested/payload") == "fake\n"
    assert not second.exists("/tmp/demo/nested/payload")


def test_remove_is_virtual_and_root_is_protected() -> None:
    fs = VirtualFileSystem()
    fs.touch("/tmp", "sample")
    fs.remove("/tmp", "sample")
    assert not fs.exists("/tmp/sample")
    try:
        fs.remove("/", "/", recursive=True, force=True)
    except VirtualFSError as exc:
        assert "refusing" in str(exc)
    else:
        raise AssertionError("virtual root removal should be refused")


def test_find_and_completion_use_virtual_nodes() -> None:
    fs = VirtualFileSystem()
    found = fs.find("/root", "/etc", "pass*", "f")
    assert found == ["/etc/passwd"]
    assert fs.complete("/root", "/etc/hos") == ["/etc/hostname", "/etc/hosts"]

