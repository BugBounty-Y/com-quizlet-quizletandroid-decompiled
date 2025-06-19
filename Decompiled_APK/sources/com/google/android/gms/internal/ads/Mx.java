package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Mx extends AbstractC2547qw {
    public final String a;
    public final Yz b;

    public Mx(String str, Yz yz) {
        this.a = str;
        this.b = yz;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2547qw
    public final boolean a() {
        return this.b != Yz.RAW;
    }

    public final String toString() {
        int iOrdinal = this.b.ordinal();
        return androidx.compose.ui.node.B.j(new StringBuilder("(typeUrl="), this.a, ", outputPrefixType=", iOrdinal != 1 ? iOrdinal != 2 ? iOrdinal != 3 ? iOrdinal != 4 ? "UNKNOWN" : "CRUNCHY" : "RAW" : "LEGACY" : "TINK", ")");
    }
}
