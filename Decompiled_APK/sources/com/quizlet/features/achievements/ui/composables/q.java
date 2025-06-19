package com.quizlet.features.achievements.ui.composables;

import com.quizlet.data.model.C4114c;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes2.dex */
public final /* synthetic */ class q implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ C4114c c;

    public /* synthetic */ q(Function1 function1, C4114c c4114c, int i) {
        this.a = i;
        this.b = function1;
        this.c = c4114c;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(this.c);
                break;
            case 1:
                this.b.invoke(this.c);
                break;
            case 2:
                this.b.invoke(this.c);
                break;
            case 3:
                this.b.invoke(this.c);
                break;
            case 4:
                this.b.invoke(this.c);
                break;
            case 5:
                this.b.invoke(this.c);
                break;
            default:
                this.b.invoke(this.c);
                break;
        }
        return Unit.a;
    }
}
