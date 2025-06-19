package com.quizlet.features.practicetest.takingtest.viewmodel;

import com.quizlet.features.practicetest.takingtest.data.D;
import com.quizlet.features.practicetest.takingtest.data.r;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class g implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ l b;

    public /* synthetic */ g(l lVar, int i) {
        this.a = i;
        this.b = lVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.F(r.a);
                break;
            case 1:
                l lVar = this.b;
                lVar.m.h(new D(lVar.B()));
                break;
            default:
                this.b.F(r.a);
                break;
        }
        return Unit.a;
    }
}
