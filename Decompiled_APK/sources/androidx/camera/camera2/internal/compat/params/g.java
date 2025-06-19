package androidx.camera.camera2.internal.compat.params;

import android.os.Build;

/* loaded from: classes.dex */
public final class g {
    public final e a;

    public g(e eVar) {
        this.a = eVar;
    }

    public static g a(Object obj) {
        if (obj == null) {
            return null;
        }
        return Build.VERSION.SDK_INT >= 31 ? new g(new f(obj)) : new g(new e(obj));
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof g)) {
            return false;
        }
        return this.a.equals(((g) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return this.a.toString();
    }
}
