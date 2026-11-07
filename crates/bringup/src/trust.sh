# All metadata utilities are fixed OS paths, independent of the candidate's PATH.
LC_ALL=C; export LC_ALL
fail() {
    printf 'QSH-REFUSE %s\n' "$boundary"
    exit 1
}
boundary=/
case "$os" in
    linux)
        if [ -x /usr/bin/stat ]; then stat=/usr/bin/stat; else stat=/bin/stat; fi
        if [ -x /usr/bin/id ]; then id=/usr/bin/id; else id=/bin/id; fi
        if [ -x /usr/bin/readlink ]; then readlink=/usr/bin/readlink; else readlink=/bin/readlink; fi ;;
    darwin) stat=/usr/bin/stat; id=/usr/bin/id; readlink=/usr/bin/readlink ;;
    *) fail ;;
esac
[ -x "$stat" ] && [ -x "$id" ] && [ -x "$readlink" ] || fail
account=$("$id" -u) || fail
case "$account" in ''|*[!0-9]*) fail ;; esac
metadata() {
    case "$os" in
        linux) record=$("$stat" -c '%a:%u' -- "$boundary" 2>/dev/null) || fail ;;
        darwin) record=$("$stat" -f '%Lp:%u' "$boundary" 2>/dev/null) || fail ;;
    esac
    bits=${record%%:*}; owner=${record#*:}
    case "$bits" in ''|*[!0-7]*) fail ;; esac
    case "$owner" in ''|*[!0-9]*) fail ;; esac
    [ "${#bits}" -le 4 ] && [ "${#owner}" -le 20 ] || fail
    [ "$owner" = 0 ] || [ "$owner" = "$account" ] || fail
    mode=$((0$bits))
}
# privacy applies only to the current route. Symlink expansion restarts at /.
reset() {
    current=/; private=0; sticky=0; boundary=/
    metadata
    directory
}
directory() {
    [ -d "$boundary" ] && [ -x "$boundary" ] || fail
    sticky=0
    if [ "$private" = 0 ] && [ $((mode & 0022)) -ne 0 ]; then
        [ $((mode & 01000)) -ne 0 ] || fail
        sticky=1
    fi
    # A writable sticky directory is never a private boundary.
    if [ "$sticky" = 0 ] && [ $((mode & 0011)) -eq 0 ]; then private=1; fi
}
case "$path" in /*) ;; *) fail ;; esac
pending=${path#/}; links=0; components=0
reset
while [ -n "$pending" ]; do
    [ "${#pending}" -le 4096 ] || fail
    components=$((components + 1)); [ "$components" -le 256 ] || fail
    case "$pending" in
        */*) part=${pending%%/*}; pending=${pending#*/} ;;
        *) part=$pending; pending= ;;
    esac
    case "$part" in ''|.) continue ;; esac
    # Dotdot is processed only after every preceding link has been expanded.
    if [ "$part" = .. ]; then
        case "$current" in /) ;; *) current=${current%/*}; [ -n "$current" ] || current=/ ;; esac
        # Rewalking the parent re-establishes its privacy rather than inheriting
        # a boundary that may have just been left.
        pending=${current#/}${pending:+/$pending}
        reset
        continue
    fi
    if [ "$current" = / ]; then boundary=/$part; else boundary=$current/$part; fi
    [ "${#boundary}" -le 4096 ] || fail
    case "$boundary" in *[[:cntrl:]]*) fail ;; esac
    if [ ! -e "$boundary" ] && [ ! -L "$boundary" ]; then
        # Absence is usable only for a final managed file, under a checked,
        # non-shared parent. It never permits directory creation under /tmp.
        if [ "$purpose" = file ] && [ -z "$pending" ] && [ "$sticky" = 0 ]; then
            printf 'QSH-TRUST %s\n' "$boundary"; exit 0
        fi
        fail
    fi
    metadata
    if [ -L "$boundary" ]; then
        [ "$purpose" != file ] || [ -n "$pending" ] || fail
        links=$((links + 1)); [ "$links" -le 40 ] || fail
        # A sentinel preserves trailing newlines, which must be refused.
        target=$("$readlink" "$boundary" && printf '.') || fail
        target=${target%.}
        # readlink appends one newline; remove exactly that newline.
        target=${target%'
'}
        case "$target" in ''|*[[:cntrl:]]*) fail ;; esac
        case "$target" in
            /*) pending=${target#/}${pending:+/$pending} ;;
            *) pending=${current#/}/$target${pending:+/$pending} ;;
        esac
        [ "${#pending}" -le 4096 ] || fail
        reset
        continue
    fi
    current=$boundary
    if [ -n "$pending" ] || [ "$purpose" = directory ]; then
        directory
    else
        [ -f "$boundary" ] && [ $((mode & 06022)) -eq 0 ] || fail
        if [ "$purpose" = execute ]; then [ -x "$boundary" ] || fail; fi
    fi
done
boundary=$current
if [ "$purpose" = directory ]; then
    # The directory itself cannot be a shared sticky installation destination.
    [ "$sticky" = 0 ] || fail
else
    [ -f "$boundary" ] || fail
fi
printf 'QSH-TRUST %s\n' "$boundary"
