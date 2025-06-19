package com.quizlet.quizletandroid.ui.globalnav.composable;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L4;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class w implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.quizletandroid.ui.globalnav.data.k b;

    public /* synthetic */ w(com.quizlet.quizletandroid.ui.globalnav.data.k kVar, int i, int i2) {
        this.a = i2;
        this.b = kVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                L4.b(this.b, interfaceC0806l, C0776c.H(1));
                break;
            default:
                L4.c(this.b, interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}
