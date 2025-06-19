package androidx.camera.core.impl;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;

/* loaded from: classes.dex */
public final class w0 implements androidx.camera.core.Z {
    public final long b;
    public final androidx.camera.core.Z c;

    public w0(long j, androidx.camera.core.Z z) {
        AbstractC3242q6.c("Timeout must be non-negative.", j >= 0);
        this.b = j;
        this.c = z;
    }

    @Override // androidx.camera.core.Z
    public final long a() {
        return this.b;
    }

    @Override // androidx.camera.core.Z
    public final androidx.camera.core.Y b(C0186z c0186z) {
        androidx.camera.core.Y yB = this.c.b(c0186z);
        long j = this.b;
        if (j > 0) {
            if (c0186z.c >= j - yB.a) {
                return androidx.camera.core.Y.d;
            }
        }
        return yB;
    }
}
