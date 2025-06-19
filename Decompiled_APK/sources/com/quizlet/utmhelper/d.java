package com.quizlet.utmhelper;

import com.quizlet.utm.a;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements c {
    public final b a(a info) {
        Intrinsics.checkNotNullParameter(info, "info");
        a.b bVarEncodeUriParams = com.quizlet.utm.a.encodeUriParams(info.a());
        return new b(bVarEncodeUriParams.getUserId(), bVarEncodeUriParams.getUtmBlob());
    }
}
