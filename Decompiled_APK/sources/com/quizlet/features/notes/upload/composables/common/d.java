package com.quizlet.features.notes.upload.composables.common;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3320b;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3531s4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3555w4;
import com.google.android.gms.internal.mlkit_vision_common.L2;
import com.google.android.gms.internal.mlkit_vision_common.R3;
import com.google.android.gms.internal.mlkit_vision_common.U2;
import com.google.android.gms.internal.mlkit_vision_common.V3;
import com.google.android.gms.internal.mlkit_vision_common.X2;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ Function0 c;

    public /* synthetic */ d(Function0 function0, Function0 function02, int i, int i2) {
        this.a = i2;
        this.b = function0;
        this.c = function02;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3320b.b(this.b, this.c, interfaceC0806l, C0776c.H(49));
                break;
            case 1:
                L2.a(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 2:
                U2.c(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 3:
                X2.b(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 4:
                R3.a(this.b, this.c, interfaceC0806l, C0776c.H(49));
                break;
            case 5:
                V3.a(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 6:
                AbstractC3531s4.a(this.b, this.c, interfaceC0806l, C0776c.H(1));
                break;
            case 7:
                AbstractC3555w4.b(this.b, this.c, interfaceC0806l, C0776c.H(7));
                break;
            default:
                AbstractC3555w4.a(this.b, this.c, interfaceC0806l, C0776c.H(7));
                break;
        }
        return Unit.a;
    }
}
