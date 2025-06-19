package com.google.android.gms.internal.mlkit_vision_barcode;

import java.util.Arrays;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.h5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3160h5 {
    public final EnumC3151g5 a;
    public final Integer b;

    public /* synthetic */ C3160h5(androidx.work.impl.model.v vVar) {
        this.a = (EnumC3151g5) vVar.b;
        this.b = (Integer) vVar.c;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C3160h5)) {
            return false;
        }
        C3160h5 c3160h5 = (C3160h5) obj;
        return com.google.android.gms.common.internal.u.l(this.a, c3160h5.a) && com.google.android.gms.common.internal.u.l(this.b, c3160h5.b) && com.google.android.gms.common.internal.u.l(null, null) && com.google.android.gms.common.internal.u.l(null, null);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b, null, null});
    }
}
