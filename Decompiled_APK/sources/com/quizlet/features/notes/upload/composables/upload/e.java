package com.quizlet.features.notes.upload.composables.upload;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3348i;
import com.quizlet.features.questiontypes.fitb.ui.l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ Function0 d;

    public /* synthetic */ e(Function0 function0, Function0 function02, boolean z, int i) {
        this.c = function0;
        this.d = function02;
        this.b = z;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3348i.c(C0776c.H(1), interfaceC0806l, this.c, this.d, this.b);
                break;
            default:
                l.e(C0776c.H(7), interfaceC0806l, this.c, this.d, this.b);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ e(boolean z, Function0 function0, Function0 function02, int i) {
        this.b = z;
        this.c = function0;
        this.d = function02;
    }
}
