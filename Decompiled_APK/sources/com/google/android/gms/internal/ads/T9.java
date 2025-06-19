package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final /* synthetic */ class T9 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ V9 b;
    public final /* synthetic */ String c;

    public /* synthetic */ T9(V9 v9, String str, int i) {
        this.a = i;
        this.b = v9;
        this.c = str;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.a.loadUrl(this.c);
                break;
            case 1:
                this.b.a.zza(this.c);
                break;
            case 2:
                this.b.a.loadData(this.c, "text/html", "UTF-8");
                break;
            default:
                this.b.a.loadData(this.c, "text/html", "UTF-8");
                break;
        }
    }
}
