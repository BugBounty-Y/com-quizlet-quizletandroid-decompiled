package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.rp, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2582rp implements InterfaceC2856y4 {
    public final int a;

    public C2582rp(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2856y4
    public final /* synthetic */ void a(L3 l3) {
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C2582rp) && this.a == ((C2582rp) obj).a;
    }

    public final int hashCode() {
        return this.a;
    }

    public final String toString() {
        return "Mp4AlternateGroup: " + this.a;
    }
}
