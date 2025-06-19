package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.jg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2230jg implements CC {
    public final /* synthetic */ int a;
    public final C1732Mb b;

    public /* synthetic */ C2230jg(C1732Mb c1732Mb, int i) {
        this.a = i;
        this.b = c1732Mb;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                Rh rh = (Rh) this.b.c;
                return rh != null ? new C2318li(rh, AbstractC2270kd.g) : new C2318li(new C2188ig(), AbstractC2270kd.g);
            case 1:
                return (Rh) this.b.c;
            default:
                return (Gh) this.b.b;
        }
    }
}
