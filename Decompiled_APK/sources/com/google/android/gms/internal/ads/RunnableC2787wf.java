package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.wf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2787wf implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C2830xf b;
    public final /* synthetic */ Throwable c;

    public /* synthetic */ RunnableC2787wf(C2830xf c2830xf, Throwable th, int i) {
        this.a = i;
        this.b = c2830xf;
        this.c = th;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.oa)).booleanValue();
                C2830xf c2830xf = this.b;
                Throwable th = this.c;
                if (!zBooleanValue) {
                    C1744Ob.a(c2830xf.a).d("AttributionReportingSampled", th);
                    break;
                } else {
                    C1744Ob.c(c2830xf.a).d("AttributionReporting", th);
                    break;
                }
            default:
                boolean zBooleanValue2 = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.oa)).booleanValue();
                C2830xf c2830xf2 = this.b;
                Throwable th2 = this.c;
                if (!zBooleanValue2) {
                    C1744Ob.a(c2830xf2.a).d("AttributionReportingSampled.getUpdatedUrlAndRegisterSource", th2);
                    break;
                } else {
                    C1744Ob.c(c2830xf2.a).d("AttributionReporting.getUpdatedUrlAndRegisterSource", th2);
                    break;
                }
        }
    }
}
