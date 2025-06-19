package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3548v3;

/* renamed from: com.google.android.gms.internal.measurement.w0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3072w0 extends W1 {
    private static final C3072w0 zzb;
    private int zzd;
    private int zze;
    private int zzf;

    static {
        C3072w0 c3072w0 = new C3072w0();
        zzb = c3072w0;
        W1.j(C3072w0.class, c3072w0);
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001᠌\u0000\u0002᠌\u0001", new Object[]{"zzd", "zze", C3047r0.e, "zzf", C3047r0.d});
        }
        if (i2 == 3) {
            return new C3072w0();
        }
        if (i2 == 4) {
            return new C3043q0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final int n() {
        int i;
        int i2 = this.zzf;
        if (i2 != 0) {
            i = 2;
            if (i2 != 1) {
                i = i2 != 2 ? 0 : 3;
            }
        } else {
            i = 1;
        }
        if (i == 0) {
            return 1;
        }
        return i;
    }

    public final int o() {
        int iA = AbstractC3548v3.a(this.zze);
        if (iA == 0) {
            return 1;
        }
        return iA;
    }
}
