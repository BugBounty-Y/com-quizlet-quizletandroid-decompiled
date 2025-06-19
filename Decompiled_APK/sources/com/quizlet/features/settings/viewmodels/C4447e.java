package com.quizlet.features.settings.viewmodels;

import androidx.lifecycle.w0;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

/* renamed from: com.quizlet.features.settings.viewmodels.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public class C4447e extends w0 {
    public final d0 b = e0.b(0, 1, null, 5);
    public final d0 c = e0.b(0, 1, null, 5);

    /* JADX WARN: Removed duplicated region for block: B:19:0x0076  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void A(kotlin.jvm.functions.Function1 r5, java.lang.Throwable r6) {
        /*
            r4 = this;
            java.lang.String r0 = "error"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            java.lang.String r0 = "onError"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r0)
            java.lang.String r0 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            boolean r0 = r6 instanceof com.quizlet.api.error.ApiErrorException
            if (r0 == 0) goto L1b
            r0 = r6
            com.quizlet.api.error.ApiErrorException r0 = (com.quizlet.api.error.ApiErrorException) r0
            com.quizlet.api.model.ApiError r0 = r0.getError()
            goto L77
        L1b:
            boolean r0 = r6 instanceof com.quizlet.api.error.ValidationErrorException
            if (r0 == 0) goto L27
            r0 = r6
            com.quizlet.api.error.ValidationErrorException r0 = (com.quizlet.api.error.ValidationErrorException) r0
            com.quizlet.api.model.ValidationError r0 = r0.getError()
            goto L77
        L27:
            boolean r0 = r6 instanceof com.quizlet.api.error.ModelErrorException
            if (r0 == 0) goto L33
            r0 = r6
            com.quizlet.api.error.ModelErrorException r0 = (com.quizlet.api.error.ModelErrorException) r0
            com.quizlet.api.model.ModelError r0 = r0.getError()
            goto L77
        L33:
            boolean r0 = r6 instanceof retrofit2.HttpException
            if (r0 == 0) goto L76
            r0 = r6
            retrofit2.HttpException r0 = (retrofit2.HttpException) r0
            java.lang.String r1 = "getString(...)"
            java.lang.String r2 = "input"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            retrofit2.K r0 = r0.c
            if (r0 == 0) goto L76
            okhttp3.I r0 = r0.c
            if (r0 == 0) goto L76
            org.json.JSONObject r2 = new org.json.JSONObject     // Catch: java.lang.Throwable -> L76
            java.lang.String r0 = r0.f()     // Catch: java.lang.Throwable -> L76
            r2.<init>(r0)     // Catch: java.lang.Throwable -> L76
            java.lang.String r0 = "error"
            org.json.JSONObject r0 = r2.getJSONObject(r0)     // Catch: java.lang.Throwable -> L76
            java.lang.String r2 = "getJSONObject(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r2)     // Catch: java.lang.Throwable -> L76
            java.lang.String r2 = "identifier"
            java.lang.String r2 = r0.getString(r2)     // Catch: java.lang.Throwable -> L76
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r1)     // Catch: java.lang.Throwable -> L76
            java.lang.String r3 = "message"
            java.lang.String r0 = r0.getString(r3)     // Catch: java.lang.Throwable -> L76
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r1)     // Catch: java.lang.Throwable -> L76
            com.quizlet.features.settings.data.interactor.exceptions.a r1 = new com.quizlet.features.settings.data.interactor.exceptions.a     // Catch: java.lang.Throwable -> L76
            r1.<init>(r2, r0)     // Catch: java.lang.Throwable -> L76
            r0 = r1
            goto L77
        L76:
            r0 = 0
        L77:
            if (r0 != 0) goto La0
            boolean r6 = r6 instanceof java.io.IOException
            if (r6 == 0) goto L81
            r6 = 2132020005(0x7f140b25, float:1.967836E38)
            goto L84
        L81:
            r6 = 2132017501(0x7f14015d, float:1.9673282E38)
        L84:
            kotlinx.coroutines.flow.d0 r0 = r4.c
            r1 = 0
            java.lang.Object[] r1 = new java.lang.Object[r1]
            java.lang.String r2 = "args"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r2)
            com.quizlet.qutils.string.f r2 = new com.quizlet.qutils.string.f
            java.util.List r1 = kotlin.collections.C4933y.P(r1)
            r2.<init>(r6, r1)
            r0.h(r2)
            com.quizlet.features.settings.data.interactor.exceptions.b r6 = com.quizlet.features.settings.data.interactor.exceptions.b.a
            r5.invoke(r6)
            return
        La0:
            r5.invoke(r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.settings.viewmodels.C4447e.A(kotlin.jvm.functions.Function1, java.lang.Throwable):void");
    }
}
