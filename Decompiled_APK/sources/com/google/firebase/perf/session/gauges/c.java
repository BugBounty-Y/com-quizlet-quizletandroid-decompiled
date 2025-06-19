package com.google.firebase.perf.session.gauges;

import com.google.firebase.perf.v1.i;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ GaugeManager b;
    public final /* synthetic */ String c;
    public final /* synthetic */ i d;

    public /* synthetic */ c(GaugeManager gaugeManager, String str, i iVar, int i) {
        this.a = i;
        this.b = gaugeManager;
        this.c = str;
        this.d = iVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.lambda$stopCollectingGauges$3(this.c, this.d);
                break;
            default:
                this.b.lambda$startCollectingGauges$2(this.c, this.d);
                break;
        }
    }
}
