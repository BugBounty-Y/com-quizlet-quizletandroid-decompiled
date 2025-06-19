package com.quizlet.features.achievements.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class v implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;

    public /* synthetic */ v(int i, int i2, long j) {
        this.a = i2;
        this.b = j;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                com.google.android.exoplayer2.drm.b.k(this.b, interfaceC0806l, C0776c.H(1));
                break;
            default:
                com.google.android.exoplayer2.drm.b.i(this.b, interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}
