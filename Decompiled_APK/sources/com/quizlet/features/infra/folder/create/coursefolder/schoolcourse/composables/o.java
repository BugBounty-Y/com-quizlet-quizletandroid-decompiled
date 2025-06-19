package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables;

import com.quizlet.features.folders.composables.J;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class o implements Function0 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    public o(int i, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f fVar) {
        this.b = i;
        this.c = fVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b + "_" + ((com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f) this.c).a;
            default:
                ((J) this.c).invoke(Integer.valueOf(this.b));
                return Unit.a;
        }
    }

    public o(J j, int i) {
        this.c = j;
        this.b = i;
    }
}
