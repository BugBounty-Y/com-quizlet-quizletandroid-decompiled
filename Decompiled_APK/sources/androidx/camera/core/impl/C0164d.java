package androidx.camera.core.impl;

/* renamed from: androidx.camera.core.impl.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0164d {
    public final Object a;

    public C0164d(Object obj) {
        this.a = obj;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C0164d)) {
            return false;
        }
        return this.a.equals(((C0164d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode() ^ 1000003;
    }

    public final String toString() {
        return android.support.v4.media.session.a.s(new StringBuilder("Identifier{value="), this.a, "}");
    }
}
