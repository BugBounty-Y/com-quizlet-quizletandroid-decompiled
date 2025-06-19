package com.airbnb.lottie;

/* loaded from: classes.dex */
public final /* synthetic */ class q implements t {
    public final /* synthetic */ u a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;

    public /* synthetic */ q(u uVar, int i, int i2) {
        this.a = uVar;
        this.b = i;
        this.c = i2;
    }

    @Override // com.airbnb.lottie.t
    public final void run() {
        u uVar = this.a;
        h hVar = uVar.a;
        int i = this.b;
        int i2 = this.c;
        if (hVar == null) {
            uVar.f.add(new q(uVar, i, i2));
        } else {
            uVar.b.k(i, i2 + 0.99f);
        }
    }
}
