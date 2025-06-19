package com.quizlet.quizletandroid.ui.widgets;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class p implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.appcompat.view.a b;
    public final /* synthetic */ androidx.glance.n c;
    public final /* synthetic */ int d;

    public /* synthetic */ p(androidx.appcompat.view.a aVar, androidx.glance.n nVar, int i, int i2) {
        this.a = i2;
        this.b = aVar;
        this.c = nVar;
        this.d = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                kotlin.jvm.a.a(this.b, this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
            default:
                org.chromium.support_lib_boundary.util.a.a(this.b, this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
        }
        return Unit.a;
    }
}
