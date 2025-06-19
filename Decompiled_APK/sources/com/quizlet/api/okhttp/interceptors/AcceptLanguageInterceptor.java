package com.quizlet.api.okhttp.interceptors;

import com.perimeterx.mobile_sdk.doctor_app.ui.p;
import com.quizlet.remote.model.notes.e;
import java.util.Locale;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.H;
import okhttp3.internal.http.f;
import okhttp3.t;
import okhttp3.u;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AcceptLanguageInterceptor implements u {

    @NotNull
    private final Function0<Locale> localeProvider;

    public AcceptLanguageInterceptor() {
        p localeProvider = new p(1);
        Intrinsics.checkNotNullParameter(localeProvider, "localeProvider");
        this.localeProvider = localeProvider;
    }

    @Override // okhttp3.u
    public final H intercept(t chain) {
        Intrinsics.checkNotNullParameter(chain, "chain");
        String languageTag = ((Locale) this.localeProvider.invoke()).toLanguageTag();
        Intrinsics.checkNotNullExpressionValue(languageTag, "toLanguageTag(...)");
        f fVar = (f) chain;
        e eVarB = fVar.e.b();
        eVarB.h("Accept-Language", languageTag);
        return fVar.b(eVarB.i());
    }
}
