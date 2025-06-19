package com.google.firebase.perf.session.gauges;

import com.google.firebase.perf.util.Timer;
import com.google.firebase.perf.v1.C3974d;

/* loaded from: classes2.dex */
public final /* synthetic */ class e implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ f b;
    public final /* synthetic */ Timer c;

    public /* synthetic */ e(f fVar, Timer timer, int i) {
        this.a = i;
        this.b = fVar;
        this.c = timer;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                f fVar = this.b;
                C3974d c3974dB = fVar.b(this.c);
                if (c3974dB != null) {
                    fVar.b.add(c3974dB);
                    break;
                }
                break;
            default:
                f fVar2 = this.b;
                C3974d c3974dB2 = fVar2.b(this.c);
                if (c3974dB2 != null) {
                    fVar2.b.add(c3974dB2);
                    break;
                }
                break;
        }
    }
}
