package com.quizlet.api.okhttp.interceptors;

import com.google.android.gms.internal.mlkit_vision_document_scanner.K6;
import com.quizlet.remote.model.notes.e;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.H;
import okhttp3.internal.http.f;
import okhttp3.t;
import okhttp3.u;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class UserAgentInterceptor implements u {

    @NotNull
    private final String userAgent;

    public UserAgentInterceptor(String versionName) {
        Intrinsics.checkNotNullParameter(versionName, "versionName");
        this.userAgent = K6.a(versionName);
    }

    @Override // okhttp3.u
    public final H intercept(t chain) {
        Intrinsics.checkNotNullParameter(chain, "chain");
        f fVar = (f) chain;
        e eVarB = fVar.e.b();
        eVarB.l("User-Agent", this.userAgent);
        return fVar.b(eVarB.i());
    }
}
