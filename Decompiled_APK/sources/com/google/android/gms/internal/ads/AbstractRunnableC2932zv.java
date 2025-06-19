package com.google.android.gms.internal.ads;

import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;

/* renamed from: com.google.android.gms.internal.ads.zv, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractRunnableC2932zv extends Mv implements Runnable {
    public static final /* synthetic */ int j = 0;
    public com.google.common.util.concurrent.e h;
    public Object i;

    public AbstractRunnableC2932zv(com.google.common.util.concurrent.e eVar, Object obj) {
        eVar.getClass();
        this.h = eVar;
        this.i = obj;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final String e() {
        com.google.common.util.concurrent.e eVar = this.h;
        Object obj = this.i;
        String strE = super.e();
        String strB = eVar != null ? android.support.v4.media.session.a.B("inputFuture=[", eVar.toString(), "], ") : "";
        if (obj != null) {
            return androidx.compose.ui.node.B.i(strB, "function=[", obj.toString(), "]");
        }
        if (strE != null) {
            return strB.concat(strE);
        }
        return null;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final void f() {
        m(this.h);
        this.h = null;
        this.i = null;
    }

    @Override // java.lang.Runnable
    public final void run() {
        com.google.common.util.concurrent.e eVar = this.h;
        Object obj = this.i;
        if (((this.a instanceof C2160hv) | (eVar == null)) || (obj == null)) {
            return;
        }
        this.h = null;
        if (eVar.isCancelled()) {
            o(eVar);
            return;
        }
        try {
            try {
                Object objU = u(obj, AbstractC2025es.P(eVar));
                this.i = null;
                v(objU);
            } catch (Throwable th) {
                try {
                    if (th instanceof InterruptedException) {
                        Thread.currentThread().interrupt();
                    }
                    h(th);
                } finally {
                    this.i = null;
                }
            }
        } catch (Error e) {
            h(e);
        } catch (CancellationException unused) {
            cancel(false);
        } catch (ExecutionException e2) {
            h(e2.getCause());
        } catch (Exception e3) {
            h(e3);
        }
    }

    public abstract Object u(Object obj, Object obj2);

    public abstract void v(Object obj);
}
