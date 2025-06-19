package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.fk, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2061fk implements InterfaceC2818x9 {
    public final C2489ph a;
    public final zzbwj b;
    public final String c;
    public final String d;

    public C2061fk(C2489ph c2489ph, Vp vp) {
        this.a = c2489ph;
        this.b = vp.l;
        this.c = vp.j;
        this.d = vp.k;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2818x9
    public final void C0(zzbwj zzbwjVar) {
        int i;
        String str;
        zzbwj zzbwjVar2 = this.b;
        if (zzbwjVar2 != null) {
            zzbwjVar = zzbwjVar2;
        }
        if (zzbwjVar != null) {
            str = zzbwjVar.a;
            i = zzbwjVar.b;
        } else {
            i = 1;
            str = "";
        }
        BinderC1966dc binderC1966dc = new BinderC1966dc(str, i);
        C2489ph c2489ph = this.a;
        c2489ph.getClass();
        c2489ph.j1(new C2326lq(12, binderC1966dc, this.c, this.d, false));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2818x9
    public final void b() {
        this.a.j1(new C1927ch(7));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2818x9
    public final void q() {
        this.a.j1(new C1927ch(6));
    }
}
