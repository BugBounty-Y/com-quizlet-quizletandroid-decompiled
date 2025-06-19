package com.quizlet.quizletandroid.ui.library;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* renamed from: com.quizlet.quizletandroid.ui.library.y, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4679y implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ com.quizlet.library.viewmodels.a c;

    public /* synthetic */ C4679y(Function1 function1, com.quizlet.library.viewmodels.a aVar, int i) {
        this.a = i;
        this.b = function1;
        this.c = aVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(((com.quizlet.library.viewmodels.w) this.c).a.a);
                break;
            case 1:
                this.b.invoke(((com.quizlet.library.viewmodels.v) this.c).a.a);
                break;
            default:
                this.b.invoke(((com.quizlet.library.viewmodels.b) this.c).a.a);
                break;
        }
        return Unit.a;
    }
}
