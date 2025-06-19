package com.quizlet.features.practicetest.results;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3339f2;
import com.quizlet.features.practicetest.results.data.t;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ t b;
    public final /* synthetic */ Function1 c;

    public /* synthetic */ a(t tVar, Function1 function1, int i, int i2) {
        this.a = i2;
        this.b = tVar;
        this.c = function1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3339f2.a(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            default:
                AbstractC3339f2.f(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}
