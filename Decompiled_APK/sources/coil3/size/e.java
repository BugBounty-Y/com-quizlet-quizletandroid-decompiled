package coil3.size;

/* loaded from: classes.dex */
public final class e implements i {
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        h hVar = h.c;
        ((e) obj).getClass();
        return hVar.equals(hVar);
    }

    public final int hashCode() {
        return h.c.hashCode();
    }

    @Override // coil3.size.i
    public final Object l(kotlin.coroutines.h hVar) {
        return h.c;
    }

    public final String toString() {
        return "RealSizeResolver(size=" + h.c + ')';
    }
}
