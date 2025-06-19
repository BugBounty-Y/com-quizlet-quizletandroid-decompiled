package androidx.camera.core;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;

/* loaded from: classes.dex */
public final class Y {
    public static final Y d = new Y(0, false, false);
    public static final Y e = new Y(500, true, false);
    public static final Y f;
    public final long a;
    public final boolean b;
    public final boolean c;

    static {
        new Y(100L, true, false);
        f = new Y(0L, false, true);
    }

    public Y(long j, boolean z, boolean z2) {
        this.b = z;
        this.a = j;
        if (z2) {
            AbstractC3242q6.c("shouldRetry must be false when completeWithoutFailure is set to true", !z);
        }
        this.c = z2;
    }
}
