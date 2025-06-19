package androidx.compose.foundation.lazy.grid;

/* renamed from: androidx.compose.foundation.lazy.grid.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0427b {
    public final long a;

    public final boolean equals(Object obj) {
        if (obj instanceof C0427b) {
            return this.a == ((C0427b) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return "GridItemSpan(packedValue=" + this.a + ')';
    }
}
