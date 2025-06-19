package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3548v3;

/* renamed from: com.google.android.gms.internal.measurement.x0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3077x0 extends W1 {
    private static final C3077x0 zzb;
    private int zzd;
    private int zze;
    private int zzf;

    static {
        C3077x0 c3077x0 = new C3077x0();
        zzb = c3077x0;
        W1.j(C3077x0.class, c3077x0);
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            C3047r0 c3047r0 = C3047r0.e;
            return new C3064u2(zzb, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001᠌\u0000\u0002᠌\u0001", new Object[]{"zzd", "zze", c3047r0, "zzf", c3047r0});
        }
        if (i2 == 3) {
            return new C3077x0();
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
        int iA = AbstractC3548v3.a(this.zzf);
        if (iA == 0) {
            return 1;
        }
        return iA;
    }

    public final int o() {
        int iA = AbstractC3548v3.a(this.zze);
        if (iA == 0) {
            return 1;
        }
        return iA;
    }
}
