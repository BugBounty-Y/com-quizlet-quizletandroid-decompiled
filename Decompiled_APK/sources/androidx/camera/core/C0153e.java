package androidx.camera.core;

/* renamed from: androidx.camera.core.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0153e {
    public final int a;
    public final Throwable b;

    public C0153e(int i, Throwable th) {
        this.a = i;
        this.b = th;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C0153e) {
            C0153e c0153e = (C0153e) obj;
            if (this.a == c0153e.a) {
                Throwable th = c0153e.b;
                Throwable th2 = this.b;
                if (th2 != null ? th2.equals(th) : th == null) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        int i = (this.a ^ 1000003) * 1000003;
        Throwable th = this.b;
        return i ^ (th == null ? 0 : th.hashCode());
    }

    public final String toString() {
        return "StateError{code=" + this.a + ", cause=" + this.b + "}";
    }
}
