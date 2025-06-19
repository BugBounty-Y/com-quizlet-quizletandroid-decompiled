package com.quizlet.api.util;

import com.quizlet.api.model.ApiThreeWrapper;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.flowable.b;
import io.reactivex.rxjava3.internal.operators.single.g;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class ApiThreeWrapperUtil {
    public static final g a(ApiThreeWrapper apiThreeWrapper) {
        b bVarD;
        if (apiThreeWrapper != null) {
            bVarD = p.f(apiThreeWrapper);
        } else {
            bVarD = p.d(new IllegalStateException("Null response body"));
            Intrinsics.checkNotNullExpressionValue(bVarD, "error(...)");
        }
        g gVarE = bVarD.e(a.b).g(a.c).e(a.d).e(a.e).e(a.f);
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }
}
