package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class q implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b b;
    public final /* synthetic */ Function0 c;

    public /* synthetic */ q(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b bVar, Function0 function0, int i) {
        this.a = i;
        this.b = bVar;
        this.c = function0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                ((com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o) this.b).m = null;
                this.c.invoke();
                break;
            default:
                ((com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o) this.b).m = null;
                this.c.invoke();
                break;
        }
        return Unit.a;
    }
}
