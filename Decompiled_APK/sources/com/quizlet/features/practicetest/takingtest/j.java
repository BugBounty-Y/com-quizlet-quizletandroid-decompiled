package com.quizlet.features.practicetest.takingtest;

import androidx.compose.runtime.InterfaceC0773a0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import com.quizlet.features.practicetest.takingtest.data.F;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class j implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ F b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ InterfaceC0773a0 d;

    public /* synthetic */ j(F f, Function0 function0, InterfaceC0773a0 interfaceC0773a0, int i) {
        this.a = i;
        this.b = f;
        this.c = function0;
        this.d = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                AbstractC3394t2.f(this.b, this.c, this.d);
                break;
            default:
                AbstractC3394t2.f(this.b, this.c, this.d);
                break;
        }
        return Unit.a;
    }
}
