package com.quizlet.explanations.solution.viewmodel;

import java.util.List;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a extends C4956o implements Function1 {
    public static final a a = new a(1, List.class, "isEmpty", "isEmpty()Z", 0);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        List p0 = (List) obj;
        Intrinsics.checkNotNullParameter(p0, "p0");
        return Boolean.valueOf(p0.isEmpty());
    }
}
