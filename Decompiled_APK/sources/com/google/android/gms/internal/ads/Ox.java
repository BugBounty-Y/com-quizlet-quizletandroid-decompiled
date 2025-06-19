package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class Ox extends AbstractC2547qw {
    public final C2420ny a;

    public Ox(C2420ny c2420ny) {
        this.a = c2420ny;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2547qw
    public final boolean a() {
        return this.a.b.z() != Yz.RAW;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof Ox)) {
            return false;
        }
        C2420ny c2420ny = ((Ox) obj).a;
        C2420ny c2420ny2 = this.a;
        if (c2420ny2.b.z().equals(c2420ny.b.z())) {
            Gz gz = c2420ny2.b;
            String strB = gz.B();
            Gz gz2 = c2420ny.b;
            if (strB.equals(gz2.B()) && gz.A().equals(gz2.A())) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        C2420ny c2420ny = this.a;
        return Objects.hash(c2420ny.b, c2420ny.a);
    }

    public final String toString() {
        C2420ny c2420ny = this.a;
        String strB = c2420ny.b.B();
        int iOrdinal = c2420ny.b.z().ordinal();
        return AbstractC0147y.e("(typeUrl=", strB, ", outputPrefixType=", iOrdinal != 1 ? iOrdinal != 2 ? iOrdinal != 3 ? iOrdinal != 4 ? "UNKNOWN" : "CRUNCHY" : "RAW" : "LEGACY" : "TINK", ")");
    }
}
