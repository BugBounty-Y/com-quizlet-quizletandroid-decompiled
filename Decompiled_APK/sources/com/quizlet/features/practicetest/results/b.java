package com.quizlet.features.practicetest.results;

import com.quizlet.assembly.compose.modals.x;
import com.quizlet.features.practicetest.results.data.m;
import com.quizlet.features.practicetest.takingtest.data.w;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ x b;
    public final /* synthetic */ Function1 c;

    public /* synthetic */ b(x xVar, Function1 function1) {
        this.b = xVar;
        this.c = function1;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        int i = this.a;
        int iIntValue = ((Integer) obj).intValue();
        boolean zBooleanValue = ((Boolean) obj2).booleanValue();
        boolean zBooleanValue2 = ((Boolean) obj3).booleanValue();
        switch (i) {
            case 0:
                this.c.invoke(new m(iIntValue, zBooleanValue, zBooleanValue2));
                this.b.a();
                break;
            default:
                this.b.a();
                this.c.invoke(new w(iIntValue, zBooleanValue, zBooleanValue2));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ b(Function1 function1, x xVar) {
        this.c = function1;
        this.b = xVar;
    }
}
