package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.lF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2309lF implements XF {
    public final XF a;
    public final J9 b;

    public C2309lF(XF xf, J9 j9) {
        this.a = xf;
        this.b = j9;
    }

    @Override // com.google.android.gms.internal.ads.XF
    public final J9 a() {
        return this.b;
    }

    public final boolean b(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C2309lF) {
            return this.a.equals(((C2309lF) obj).a);
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.XF
    public final int e(int i) {
        return this.a.e(i);
    }

    public final boolean equals(Object obj) {
        if (b(obj) && (obj instanceof C2309lF)) {
            return this.b.equals(((C2309lF) obj).b);
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.XF
    public final int f() {
        return this.a.f();
    }

    @Override // com.google.android.gms.internal.ads.XF
    public final int g() {
        return this.a.g();
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    @Override // com.google.android.gms.internal.ads.XF
    public final int u(int i) {
        return this.a.u(i);
    }

    @Override // com.google.android.gms.internal.ads.XF
    public final C1832aG zza(int i) {
        return this.b.d[this.a.u(i)];
    }

    @Override // com.google.android.gms.internal.ads.XF
    public final C1832aG zzb() {
        return this.b.d[this.a.f()];
    }
}
