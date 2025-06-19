package com.quizlet.api.okhttp.interceptors;

import com.quizlet.infra.contracts.session.a;
import com.quizlet.remote.model.notes.e;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.C;
import okhttp3.H;
import okhttp3.internal.http.f;
import okhttp3.s;
import okhttp3.t;
import okhttp3.u;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AppSessionInterceptor implements u {

    @NotNull
    private final a appSessionProvider;

    @NotNull
    private final s baseUrl;

    @Metadata
    public static final class Companion {
    }

    public AppSessionInterceptor(a appSessionProvider, s baseUrl) {
        Intrinsics.checkNotNullParameter(appSessionProvider, "appSessionProvider");
        Intrinsics.checkNotNullParameter(baseUrl, "baseUrl");
        this.appSessionProvider = appSessionProvider;
        this.baseUrl = baseUrl;
    }

    @Override // okhttp3.u
    public final H intercept(t chain) {
        Intrinsics.checkNotNullParameter(chain, "chain");
        f fVar = (f) chain;
        C c = fVar.e;
        e eVarB = c.b();
        if (Intrinsics.b(c.a.d, this.baseUrl.d)) {
            String string = ((AppSessionIdProvider) this.appSessionProvider).a().toString();
            Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
            eVarB.h("X-QUIZLET-APP-SESSION-ID", string);
        }
        return fVar.b(eVarB.i());
    }
}
