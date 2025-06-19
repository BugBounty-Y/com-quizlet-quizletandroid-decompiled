package com.quizlet.features.notes.detail.composables.magicnotesdetail;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3207m7;
import com.google.android.gms.internal.mlkit_vision_camera.J2;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.notes.detail.composables.magicnotesdetail.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4389h implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ int d;

    public /* synthetic */ C4389h(Function0 function0, Function0 function02, int i, int i2) {
        this.a = i2;
        this.b = function0;
        this.c = function02;
        this.d = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        Integer num = (Integer) obj2;
        switch (this.a) {
            case 0:
                num.getClass();
                AbstractC3207m7.a(this.b, this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
            default:
                num.intValue();
                J2.a(this.b, this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
        }
        return Unit.a;
    }
}
