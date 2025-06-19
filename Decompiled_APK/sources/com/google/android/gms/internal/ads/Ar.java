package com.google.android.gms.internal.ads;

import com.amazon.device.ads.DtbDeviceDataRetriever;
import java.util.Locale;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class Ar {
    public final String a;
    public final com.google.android.gms.ads.c b;

    public /* synthetic */ Ar(Fp fp) {
        this.a = (String) fp.b;
        this.b = (com.google.android.gms.ads.c) fp.c;
    }

    public final String a() {
        com.google.android.gms.ads.c cVar = this.b;
        return cVar == null ? DtbDeviceDataRetriever.ORIENTATION_UNKNOWN : cVar.name().toLowerCase(Locale.ENGLISH);
    }

    public final boolean equals(Object obj) {
        com.google.android.gms.ads.c cVar;
        com.google.android.gms.ads.c cVar2;
        if (obj instanceof Ar) {
            Ar ar = (Ar) obj;
            if (this.a.equals(ar.a) && (cVar = this.b) != null && (cVar2 = ar.b) != null && cVar.equals(cVar2)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Objects.hash(this.a, this.b);
    }
}
