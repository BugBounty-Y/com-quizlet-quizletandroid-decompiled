package com.quizlet.features.practicetest.takingtest;

import androidx.compose.runtime.InterfaceC0773a0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import com.quizlet.features.practicetest.takingtest.data.F;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class h implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ F b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ InterfaceC0773a0 d;

    public /* synthetic */ h(F f, Function1 function1, InterfaceC0773a0 interfaceC0773a0, int i) {
        this.a = i;
        this.b = f;
        this.c = function1;
        this.d = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        InterfaceC0773a0 interfaceC0773a0 = this.d;
        Function1 function1 = this.c;
        F f = this.b;
        switch (this.a) {
            case 0:
                AbstractC3394t2.g(f, function1, interfaceC0773a0);
                break;
            case 1:
                if (f.i != f.b) {
                    break;
                } else {
                    break;
                }
            case 2:
                AbstractC3394t2.g(f, function1, interfaceC0773a0);
                break;
            default:
                if (f.i == f.b) {
                    AbstractC3394t2.g(f, function1, interfaceC0773a0);
                    Unit unit = Unit.a;
                } else {
                    function1.invoke(com.quizlet.features.practicetest.takingtest.data.o.a);
                    Unit unit2 = Unit.a;
                }
                break;
        }
        return Unit.a;
    }
}
