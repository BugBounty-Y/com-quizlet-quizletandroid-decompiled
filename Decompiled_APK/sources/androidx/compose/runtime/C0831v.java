package androidx.compose.runtime;

/* renamed from: androidx.compose.runtime.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0831v {
    public final C0833w a;

    public C0831v(C0833w c0833w) {
        this.a = c0833w;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof C0831v) {
            return this.a.equals(((C0831v) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode() * 31;
    }
}
