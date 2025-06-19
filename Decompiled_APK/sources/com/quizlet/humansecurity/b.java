package com.quizlet.humansecurity;

import com.perimeterx.mobile_sdk.main.PXInterceptor;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.H;
import okhttp3.internal.http.f;
import okhttp3.t;
import okhttp3.u;

/* loaded from: classes3.dex */
public final class b implements u {
    public final c a;
    public final PXInterceptor b;

    public b(c humanSecurityManager, PXInterceptor pxInterceptor) {
        Intrinsics.checkNotNullParameter(humanSecurityManager, "humanSecurityManager");
        Intrinsics.checkNotNullParameter(pxInterceptor, "pxInterceptor");
        this.a = humanSecurityManager;
        this.b = pxInterceptor;
    }

    @Override // okhttp3.u
    public final H intercept(t chain) {
        Intrinsics.checkNotNullParameter(chain, "chain");
        if (this.a.c) {
            return this.b.intercept(chain);
        }
        f fVar = (f) chain;
        return fVar.b(fVar.e);
    }
}
