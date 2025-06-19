package com.airbnb.lottie;

/* loaded from: classes.dex */
public final /* synthetic */ class m implements t {
    public final /* synthetic */ int a;
    public final /* synthetic */ u b;
    public final /* synthetic */ String c;

    public /* synthetic */ m(u uVar, String str, int i) {
        this.a = i;
        this.b = uVar;
        this.c = str;
    }

    @Override // com.airbnb.lottie.t
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.r(this.c);
                break;
            case 1:
                this.b.q(this.c);
                break;
            default:
                this.b.t(this.c);
                break;
        }
    }
}
