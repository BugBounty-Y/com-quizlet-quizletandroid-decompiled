package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final /* synthetic */ class Bn implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Cn b;

    public /* synthetic */ Bn(Cn cn, int i) {
        this.a = i;
        this.b = cn;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Cn cn = this.b;
                synchronized (cn) {
                    cn.b.clear();
                    cn.a.clear();
                    cn.e.clear();
                    cn.d.clear();
                    cn.g();
                    cn.h();
                    cn.e();
                }
                return;
            default:
                Cn cn2 = this.b;
                cn2.f.execute(new Bn(cn2, 0));
                return;
        }
    }
}
