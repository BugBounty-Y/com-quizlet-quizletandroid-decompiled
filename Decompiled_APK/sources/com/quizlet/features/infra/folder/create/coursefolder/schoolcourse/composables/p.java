package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p implements Function1 {
    public final /* synthetic */ com.quizlet.explanations.questiondetail.ui.composables.l a;
    public final /* synthetic */ int b;

    public p(com.quizlet.explanations.questiondetail.ui.composables.l lVar, int i) {
        this.a = lVar;
        this.b = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f it2 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        this.a.invoke(it2, Long.valueOf(this.b));
        return Unit.a;
    }
}
