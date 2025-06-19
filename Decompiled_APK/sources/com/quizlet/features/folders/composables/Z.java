package com.quizlet.features.folders.composables;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class Z implements Function1 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ kotlinx.collections.immutable.b b;
    public final /* synthetic */ Function1 c;

    public /* synthetic */ Z(Function1 function1, kotlinx.collections.immutable.b bVar) {
        this.c = function1;
        this.b = bVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                int iIntValue = ((Integer) obj).intValue();
                kotlinx.collections.immutable.b bVar = this.b;
                this.c.invoke(new com.quizlet.features.folders.data.M(((com.quizlet.features.infra.models.folders.c) bVar.get(iIntValue)).a, ((com.quizlet.features.infra.models.folders.c) bVar.get(iIntValue)).b));
                break;
            default:
                androidx.compose.foundation.lazy.g LazyColumn = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                kotlinx.collections.immutable.b bVar2 = this.b;
                LazyColumn.q(bVar2.size(), null, new com.quizlet.assembly.compose.menu.e(bVar2, 10), new androidx.compose.runtime.internal.d(true, -632812321, new com.quizlet.features.infra.folder.create.coursefolder.composable.m(bVar2, this.c, 2)));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ Z(kotlinx.collections.immutable.b bVar, Function1 function1) {
        this.b = bVar;
        this.c = function1;
    }
}
