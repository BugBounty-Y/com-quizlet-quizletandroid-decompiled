package com.airbnb.lottie;

/* loaded from: classes.dex */
public final /* synthetic */ class p implements t {
    public final /* synthetic */ int a;
    public final /* synthetic */ u b;
    public final /* synthetic */ float c;

    public /* synthetic */ p(u uVar, float f, int i) {
        this.a = i;
        this.b = uVar;
        this.c = f;
    }

    @Override // com.airbnb.lottie.t
    public final void run() {
        switch (this.a) {
            case 0:
                u uVar = this.b;
                h hVar = uVar.a;
                float f = this.c;
                if (hVar != null) {
                    float f2 = com.airbnb.lottie.utils.g.f(hVar.l, hVar.m, f);
                    com.airbnb.lottie.utils.e eVar = uVar.b;
                    eVar.k(eVar.j, f2);
                    break;
                } else {
                    uVar.f.add(new p(uVar, f, 0));
                    break;
                }
            case 1:
                u uVar2 = this.b;
                h hVar2 = uVar2.a;
                float f3 = this.c;
                if (hVar2 != null) {
                    uVar2.s((int) com.airbnb.lottie.utils.g.f(hVar2.l, hVar2.m, f3));
                    break;
                } else {
                    uVar2.f.add(new p(uVar2, f3, 1));
                    break;
                }
            default:
                this.b.u(this.c);
                break;
        }
    }
}
