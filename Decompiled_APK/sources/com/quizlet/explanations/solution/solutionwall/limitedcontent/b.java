package com.quizlet.explanations.solution.solutionwall.limitedcontent;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3171i7;
import com.google.android.gms.internal.mlkit_vision_barcode.N4;
import com.google.android.gms.internal.mlkit_vision_camera.A1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3435c3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3555w4;
import com.google.android.gms.internal.mlkit_vision_common.D2;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;

    public /* synthetic */ b(int i, int i2, Function0 function0) {
        this.a = i2;
        this.b = function0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                com.google.mlkit.vision.common.internal.c.a(this.b, interfaceC0806l, C0776c.H(7));
                break;
            case 1:
                AbstractC3171i7.d(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 2:
                AbstractC3328d.e(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 3:
                A1.d(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 4:
                K1.e(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 5:
                D2.d(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 6:
                D2.b(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 7:
                D2.c(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 8:
                D2.e(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 9:
                AbstractC3435c3.b(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 10:
                AbstractC3448e4.c(this.b, interfaceC0806l, C0776c.H(1));
                break;
            case 11:
                AbstractC3555w4.c(this.b, interfaceC0806l, C0776c.H(7));
                break;
            default:
                N4.b(this.b, interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}
