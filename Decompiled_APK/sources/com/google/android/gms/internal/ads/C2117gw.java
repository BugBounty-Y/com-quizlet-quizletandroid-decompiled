package com.google.android.gms.internal.ads;

import java.util.concurrent.Callable;

/* renamed from: com.google.android.gms.internal.ads.gw, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2117gw extends Vv {
    public final /* synthetic */ int c = 0;
    public final /* synthetic */ RunnableFutureC2161hw d;
    public final Object e;

    public C2117gw(RunnableFutureC2161hw runnableFutureC2161hw, Ev ev) {
        this.d = runnableFutureC2161hw;
        this.e = ev;
    }

    @Override // com.google.android.gms.internal.ads.Vv
    public final Object a() {
        switch (this.c) {
            case 0:
                Ev ev = (Ev) this.e;
                com.google.common.util.concurrent.e eVarMo19zza = ev.mo19zza();
                if (eVarMo19zza != null) {
                    return eVarMo19zza;
                }
                throw new NullPointerException(AbstractC2025es.r("AsyncCallable.call returned null instead of a Future. Did you mean to return immediateFuture(null)? %s", ev));
            default:
                return ((Callable) this.e).call();
        }
    }

    @Override // com.google.android.gms.internal.ads.Vv
    public final String b() {
        switch (this.c) {
            case 0:
                return ((Ev) this.e).toString();
            default:
                return ((Callable) this.e).toString();
        }
    }

    @Override // com.google.android.gms.internal.ads.Vv
    public final void d(Throwable th) {
        switch (this.c) {
            case 0:
                this.d.h(th);
                break;
            default:
                this.d.h(th);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Vv
    public final void e(Object obj) {
        switch (this.c) {
            case 0:
                this.d.o((com.google.common.util.concurrent.e) obj);
                break;
            default:
                this.d.g(obj);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Vv
    public final boolean f() {
        switch (this.c) {
        }
        return this.d.isDone();
    }

    public C2117gw(RunnableFutureC2161hw runnableFutureC2161hw, Callable callable) {
        this.d = runnableFutureC2161hw;
        callable.getClass();
        this.e = callable;
    }
}
