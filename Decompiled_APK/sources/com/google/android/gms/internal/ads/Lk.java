package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final /* synthetic */ class Lk implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Kk b;
    public final /* synthetic */ String c;

    public /* synthetic */ Lk(Kk kk, String str, int i) {
        this.a = i;
        this.b = kk;
        this.c = str;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.d.zza(this.c);
                break;
            default:
                this.b.d.zza(this.c);
                break;
        }
    }
}
