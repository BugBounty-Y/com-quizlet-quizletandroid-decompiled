package com.google.ads.conversiontracking;

import android.util.Log;
import com.google.android.gms.measurement.internal.AbstractC3886p;
import com.google.android.gms.measurement.internal.C3884o;
import com.google.android.gms.measurement.internal.O0;
import com.google.android.gms.measurement.internal.Y;
import io.reactivex.rxjava3.internal.operators.observable.w0;

/* loaded from: classes2.dex */
public final class i implements Runnable {
    public final /* synthetic */ int a;
    public long b;
    public final Object c;

    public /* synthetic */ i(AbstractC3886p abstractC3886p, long j, int i) {
        this.a = i;
        this.b = j;
        this.c = abstractC3886p;
    }

    /* JADX WARN: Type inference failed for: r0v6, types: [io.reactivex.rxjava3.internal.operators.observable.w0, java.lang.Object] */
    @Override // java.lang.Runnable
    public final void run() throws Throwable {
        h hVar;
        switch (this.a) {
            case 0:
                try {
                    ((l) this.c).e = true;
                    while (true) {
                        synchronized (((l) this.c).a) {
                            while (((l) this.c).b.isEmpty()) {
                                try {
                                    l lVar = (l) this.c;
                                    lVar.d = false;
                                    lVar.a.wait();
                                } finally {
                                }
                            }
                            l lVar2 = (l) this.c;
                            lVar2.d = true;
                            hVar = (h) lVar2.b.remove(0);
                        }
                        if (hVar != null) {
                            if (r.d(((l) this.c).c, hVar.e, hVar.f, hVar.b)) {
                                int iA = ((l) this.c).a(hVar);
                                if (iA == 2) {
                                    ((l) this.c).f.d(hVar);
                                    this.b = 0L;
                                } else if (iA == 0) {
                                    ((l) this.c).f.h(hVar);
                                    long j = this.b;
                                    if (j == 0) {
                                        this.b = 1000L;
                                    } else {
                                        this.b = Math.min(j * 2, 60000L);
                                    }
                                    Thread.sleep(this.b);
                                } else {
                                    ((l) this.c).f.h(hVar);
                                    this.b = 0L;
                                }
                            } else {
                                ((l) this.c).f.d(hVar);
                            }
                        }
                    }
                } catch (InterruptedException unused) {
                    Log.w("GoogleConversionReporter", "Dispatch thread is interrupted.");
                    ((l) this.c).e = false;
                    return;
                }
            case 1:
                ((C3884o) this.c).Y(this.b);
                return;
            case 2:
                O0 o0 = (O0) this.c;
                C3884o c3884o = ((Y) o0.b).q;
                Y.g(c3884o);
                c3884o.V(this.b);
                o0.f = null;
                return;
            default:
                this.c.c(this.b);
                return;
        }
    }

    public i(l lVar) {
        this.a = 0;
        this.c = lVar;
        this.b = 0L;
    }

    public i(long j, w0 w0Var) {
        this.a = 3;
        this.b = j;
        this.c = w0Var;
    }
}
