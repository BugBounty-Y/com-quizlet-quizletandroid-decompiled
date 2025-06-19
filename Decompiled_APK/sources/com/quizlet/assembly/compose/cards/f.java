package com.quizlet.assembly.compose.cards;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3659k6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3690o5;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class f implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ int c;

    public /* synthetic */ f(String str, int i) {
        this.a = 2;
        this.b = str;
        this.c = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3690o5.a(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 1:
                AbstractC3690o5.c(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            default:
                AbstractC3659k6.c(this.b, interfaceC0806l, C0776c.H(this.c | 1));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ f(String str, int i, int i2, int i3) {
        this.a = i3;
        this.b = str;
        this.c = i;
    }
}
