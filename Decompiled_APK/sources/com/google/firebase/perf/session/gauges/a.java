package com.google.firebase.perf.session.gauges;

import com.google.firebase.perf.util.Timer;
import com.google.firebase.perf.v1.k;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ b b;
    public final /* synthetic */ Timer c;

    public /* synthetic */ a(b bVar, Timer timer, int i) {
        this.a = i;
        this.b = bVar;
        this.c = timer;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                b bVar = this.b;
                k kVarB = bVar.b(this.c);
                if (kVarB != null) {
                    bVar.a.add(kVarB);
                    break;
                }
                break;
            default:
                b bVar2 = this.b;
                k kVarB2 = bVar2.b(this.c);
                if (kVarB2 != null) {
                    bVar2.a.add(kVarB2);
                    break;
                }
                break;
        }
    }
}
