package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* renamed from: com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4340f implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f c;

    public /* synthetic */ C4340f(Function1 function1, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f fVar, int i) {
        this.a = i;
        this.b = function1;
        this.c = fVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(this.c);
                break;
            default:
                this.b.invoke(this.c);
                break;
        }
        return Unit.a;
    }
}
