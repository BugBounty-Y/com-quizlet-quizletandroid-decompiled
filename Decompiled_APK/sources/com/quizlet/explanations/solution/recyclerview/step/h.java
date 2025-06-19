package com.quizlet.explanations.solution.recyclerview.step;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.D0;
import com.google.android.gms.internal.mlkit_vision_camera.S2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class h implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    public /* synthetic */ h(String str, int i, int i2) {
        this.a = i2;
        this.b = str;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                i.f(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 1:
                S2.c(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 2:
                S2.a(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 3:
                E6.m(this.b, interfaceC0806l, C0776c.H(1));
                break;
            default:
                D0.f(this.b, interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}
