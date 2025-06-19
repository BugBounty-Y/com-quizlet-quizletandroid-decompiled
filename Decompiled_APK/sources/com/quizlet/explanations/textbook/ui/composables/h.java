package com.quizlet.explanations.textbook.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import org.slf4j.helpers.k;

/* loaded from: classes2.dex */
public final /* synthetic */ class h implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ h(String str, boolean z, q qVar, int i) {
        this.c = str;
        this.b = z;
        this.d = qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                int iH = C0776c.H(1);
                k.a(this.b, (Function1) this.c, (Function1) this.d, interfaceC0806l, iH);
                break;
            default:
                int iH2 = C0776c.H(1);
                S5.e((String) this.c, this.b, (q) this.d, interfaceC0806l, iH2);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ h(boolean z, Function1 function1, Function1 function12, int i) {
        this.b = z;
        this.c = function1;
        this.d = function12;
    }
}
