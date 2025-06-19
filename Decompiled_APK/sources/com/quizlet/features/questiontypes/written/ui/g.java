package com.quizlet.features.questiontypes.written.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3467i;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class g implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.runtime.internal.d b;

    public /* synthetic */ g(androidx.compose.runtime.internal.d dVar, int i, int i2) {
        this.a = i2;
        this.b = dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3467i.b(this.b, interfaceC0806l, C0776c.H(7));
                break;
            default:
                android.adservices.topics.a.a(this.b, interfaceC0806l, C0776c.H(7));
                break;
        }
        return Unit.a;
    }
}
