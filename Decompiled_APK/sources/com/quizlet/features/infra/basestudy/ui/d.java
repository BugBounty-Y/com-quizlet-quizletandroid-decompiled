package com.quizlet.features.infra.basestudy.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3314z5;
import com.google.android.gms.internal.mlkit_vision_common.T3;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ q d;
    public final /* synthetic */ int e;

    public /* synthetic */ d(int i, int i2, q qVar, String str, Function1 function1) {
        this.a = i2;
        this.b = str;
        this.c = function1;
        this.d = qVar;
        this.e = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3314z5.b(C0776c.H(this.e | 1), interfaceC0806l, this.d, this.b, this.c);
                break;
            default:
                T3.a(C0776c.H(this.e | 1), interfaceC0806l, this.d, this.b, this.c);
                break;
        }
        return Unit.a;
    }
}
