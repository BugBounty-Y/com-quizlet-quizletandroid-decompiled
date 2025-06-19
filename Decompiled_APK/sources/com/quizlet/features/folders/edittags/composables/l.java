package com.quizlet.features.folders.edittags.composables;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class l implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.folders.edittags.viewmodel.c b;

    public /* synthetic */ l(com.quizlet.features.folders.edittags.viewmodel.c cVar, int i) {
        this.a = i;
        this.b = cVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        String it2 = (String) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.A(new com.quizlet.features.folders.edittags.data.b(it2));
                break;
            default:
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.A(new com.quizlet.features.folders.edittags.data.b(it2));
                break;
        }
        return Unit.a;
    }
}
