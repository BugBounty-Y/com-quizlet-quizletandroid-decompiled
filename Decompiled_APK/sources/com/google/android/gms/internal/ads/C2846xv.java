package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.xv, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2846xv extends AbstractRunnableC2932zv {
    @Override // com.google.android.gms.internal.ads.AbstractRunnableC2932zv
    public final Object u(Object obj, Object obj2) {
        Fv fv = (Fv) obj;
        com.google.common.util.concurrent.e eVarB = fv.b(obj2);
        if (eVarB != null) {
            return eVarB;
        }
        throw new NullPointerException(AbstractC2025es.r("AsyncFunction.apply returned null instead of a Future. Did you mean to return immediateFuture(null)? %s", fv));
    }

    @Override // com.google.android.gms.internal.ads.AbstractRunnableC2932zv
    public final /* synthetic */ void v(Object obj) {
        o((com.google.common.util.concurrent.e) obj);
    }
}
