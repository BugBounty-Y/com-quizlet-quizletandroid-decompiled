package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.concurrent.ExecutionException;

/* renamed from: com.google.android.gms.internal.ads.gv, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractRunnableC2116gv extends Mv implements Runnable {
    public static final /* synthetic */ int k = 0;
    public com.google.common.util.concurrent.e h;
    public Class i;
    public Object j;

    public AbstractRunnableC2116gv(com.google.common.util.concurrent.e eVar, Class cls, Object obj) {
        eVar.getClass();
        this.h = eVar;
        this.i = cls;
        this.j = obj;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final String e() {
        com.google.common.util.concurrent.e eVar = this.h;
        Class cls = this.i;
        Object obj = this.j;
        String strE = super.e();
        String strB = eVar != null ? android.support.v4.media.session.a.B("inputFuture=[", eVar.toString(), "], ") : "";
        if (cls == null || obj == null) {
            if (strE != null) {
                return strB.concat(strE);
            }
            return null;
        }
        return strB + "exceptionType=[" + cls.toString() + "], fallback=[" + obj.toString() + "]";
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final void f() {
        m(this.h);
        this.h = null;
        this.i = null;
        this.j = null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // java.lang.Runnable
    public final void run() {
        com.google.common.util.concurrent.e eVar = this.h;
        Class cls = this.i;
        Object obj = this.j;
        if (((obj == null) || ((eVar == 0) | (cls == null))) || (this.a instanceof C2160hv)) {
            return;
        }
        this.h = null;
        try {
            th = eVar instanceof AbstractC2246jw ? ((AbstractC2246jw) eVar).c() : null;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause == null) {
                cause = new NullPointerException(AbstractC0147y.e("Future type ", String.valueOf(eVar.getClass()), " threw ", String.valueOf(e.getClass()), " without a cause"));
            }
            th = cause;
        } catch (Throwable th) {
            th = th;
        }
        Object objP = th == null ? AbstractC2025es.P(eVar) : null;
        if (th == null) {
            g(objP);
            return;
        }
        if (!cls.isInstance(th)) {
            o(eVar);
            return;
        }
        try {
            Object objU = u(obj, th);
            this.i = null;
            this.j = null;
            v(objU);
        } catch (Throwable th2) {
            try {
                if (th2 instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                h(th2);
            } finally {
                this.i = null;
                this.j = null;
            }
        }
    }

    public abstract Object u(Object obj, Throwable th);

    public abstract void v(Object obj);
}
