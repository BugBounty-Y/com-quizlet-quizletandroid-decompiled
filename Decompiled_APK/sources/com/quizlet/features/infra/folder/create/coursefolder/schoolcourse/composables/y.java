package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class y implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x c;

    public /* synthetic */ y(Function1 function1, com.quizlet.assembly.compose.modals.x xVar, int i) {
        this.a = i;
        this.b = function1;
        this.c = xVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.a it2 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.a) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.invoke(it2);
                if (it2.a > 0) {
                    this.c.a();
                }
                break;
            case 1:
                com.quizlet.features.infra.folder.menu.data.b item = (com.quizlet.features.infra.folder.menu.data.b) obj;
                Intrinsics.checkNotNullParameter(item, "item");
                this.b.invoke(item);
                this.c.a();
                break;
            case 2:
                com.quizlet.features.infra.folder.menu.data.g item2 = (com.quizlet.features.infra.folder.menu.data.g) obj;
                Intrinsics.checkNotNullParameter(item2, "item");
                this.b.invoke(item2);
                if (item2 instanceof com.quizlet.features.infra.folder.menu.data.c) {
                    this.c.a();
                }
                break;
            case 3:
                com.quizlet.features.infra.folder.study.data.a it3 = (com.quizlet.features.infra.folder.study.data.a) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                this.b.invoke(it3);
                this.c.a();
                break;
            default:
                Integer num = (Integer) obj;
                num.intValue();
                this.b.invoke(num);
                this.c.a();
                break;
        }
        return Unit.a;
    }
}
