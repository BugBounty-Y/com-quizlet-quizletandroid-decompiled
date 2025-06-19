package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.vd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2742vd implements Runnable {
    public final /* synthetic */ int a;
    public boolean b;
    public final C2785wd c;

    public RunnableC2742vd(C2785wd c2785wd) {
        this.a = 2;
        this.b = false;
        this.c = c2785wd;
    }

    public void a() {
        this.b = true;
        this.c.l();
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.c.c("windowFocusChanged", "hasWindowFocus", String.valueOf(this.b));
                break;
            case 1:
                this.c.c("windowVisibilityChanged", "isVisible", String.valueOf(this.b));
                break;
            default:
                if (!this.b) {
                    this.c.l();
                    com.google.android.gms.ads.internal.util.B b = com.google.android.gms.ads.internal.util.F.l;
                    b.removeCallbacks(this);
                    b.postDelayed(this, 250L);
                    break;
                }
                break;
        }
    }

    public /* synthetic */ RunnableC2742vd(C2785wd c2785wd, boolean z, int i) {
        this.a = i;
        this.c = c2785wd;
        this.b = z;
    }
}
