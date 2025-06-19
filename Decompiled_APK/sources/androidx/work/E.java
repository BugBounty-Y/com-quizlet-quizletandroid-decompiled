package androidx.work;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3398u2;

/* loaded from: classes.dex */
public final class E extends AbstractC3398u2 {
    public final Throwable a;

    public E(Throwable th) {
        this.a = th;
    }

    public final String toString() {
        return "FAILURE (" + this.a.getMessage() + ")";
    }
}
