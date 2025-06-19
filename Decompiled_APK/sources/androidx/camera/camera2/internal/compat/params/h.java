package androidx.camera.camera2.internal.compat.params;

import android.hardware.camera2.params.OutputConfiguration;
import android.os.Build;
import android.view.Surface;

/* loaded from: classes.dex */
public final class h {
    public final j a;

    public h(int i, Surface surface) {
        int i2 = Build.VERSION.SDK_INT;
        if (i2 >= 33) {
            this.a = new m(new OutputConfiguration(i, surface));
        } else if (i2 >= 28) {
            this.a = new l(new k(new OutputConfiguration(i, surface)));
        } else {
            this.a = new j(new i(new OutputConfiguration(i, surface)));
        }
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof h)) {
            return false;
        }
        return this.a.equals(((h) obj).a);
    }

    public final int hashCode() {
        return this.a.a.hashCode();
    }

    public h(j jVar) {
        this.a = jVar;
    }
}
