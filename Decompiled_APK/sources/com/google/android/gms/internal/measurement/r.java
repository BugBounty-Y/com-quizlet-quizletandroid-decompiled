package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.ads.C1721Kc;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class r implements InterfaceC3027n {
    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final InterfaceC3027n c(String str, C1721Kc c1721Kc, ArrayList arrayList) {
        throw new IllegalStateException("Undefined has no function ".concat(str));
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        return obj instanceof r;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Double g() {
        return Double.valueOf(Double.NaN);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Boolean h() {
        return Boolean.FALSE;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final InterfaceC3027n j() {
        return InterfaceC3027n.Q0;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Iterator k() {
        return null;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final String zzi() {
        return "undefined";
    }
}
