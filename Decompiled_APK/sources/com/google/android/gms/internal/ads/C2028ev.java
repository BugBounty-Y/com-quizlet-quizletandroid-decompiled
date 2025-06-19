package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.ev, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2028ev extends AbstractRunnableC2116gv {
    @Override // com.google.android.gms.internal.ads.AbstractRunnableC2116gv
    public final Object u(Object obj, Throwable th) {
        Fv fv = (Fv) obj;
        com.google.common.util.concurrent.e eVarB = fv.b(th);
        if (eVarB != null) {
            return eVarB;
        }
        throw new NullPointerException(AbstractC2025es.r("AsyncFunction.apply returned null instead of a Future. Did you mean to return immediateFuture(null)? %s", fv));
    }

    @Override // com.google.android.gms.internal.ads.AbstractRunnableC2116gv
    public final /* synthetic */ void v(Object obj) {
        o((com.google.common.util.concurrent.e) obj);
    }
}
