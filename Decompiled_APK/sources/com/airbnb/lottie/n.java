package com.airbnb.lottie;

/* loaded from: classes.dex */
public final /* synthetic */ class n implements t {
    public final /* synthetic */ int a;
    public final /* synthetic */ u b;
    public final /* synthetic */ int c;

    public /* synthetic */ n(u uVar, int i, int i2) {
        this.a = i2;
        this.b = uVar;
        this.c = i;
    }

    @Override // com.airbnb.lottie.t
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.p(this.c);
                break;
            case 1:
                this.b.s(this.c);
                break;
            default:
                this.b.o(this.c);
                break;
        }
    }
}
