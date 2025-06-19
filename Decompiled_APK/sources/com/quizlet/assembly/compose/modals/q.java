package com.quizlet.assembly.compose.modals;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes2.dex */
public final /* synthetic */ class q implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ Function0 c;

    public /* synthetic */ q(int i, Function0 function0, Function0 function02) {
        this.a = i;
        this.b = function0;
        this.c = function02;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke();
                this.c.invoke();
                break;
            default:
                this.b.invoke();
                this.c.invoke();
                break;
        }
        return Unit.a;
    }
}
