package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final /* synthetic */ class X9 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ V9 b;

    public /* synthetic */ X9(V9 v9, int i) {
        this.a = i;
        this.b = v9;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.a();
                break;
            case 1:
                this.b.a();
                break;
            default:
                C2217j9 c2217j9 = AbstractC2346m9.o;
                V9 v9 = this.b;
                v9.o("/result", c2217j9);
                v9.a();
                break;
        }
    }
}
