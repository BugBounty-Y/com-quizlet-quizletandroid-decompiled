package androidx.camera.core;

import android.view.Surface;

/* renamed from: androidx.camera.core.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0157i {
    public final int a;
    public final Surface b;

    public C0157i(int i, Surface surface) {
        this.a = i;
        if (surface == null) {
            throw new NullPointerException("Null surface");
        }
        this.b = surface;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C0157i)) {
            return false;
        }
        C0157i c0157i = (C0157i) obj;
        return this.a == c0157i.a && this.b.equals(c0157i.b);
    }

    public final int hashCode() {
        return this.b.hashCode() ^ ((this.a ^ 1000003) * 1000003);
    }

    public final String toString() {
        return "Result{resultCode=" + this.a + ", surface=" + this.b + "}";
    }
}
