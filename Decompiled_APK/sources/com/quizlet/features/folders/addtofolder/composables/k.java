package com.quizlet.features.folders.addtofolder.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.C0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class k implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.folders.addtofolder.data.u b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ String d;
    public final /* synthetic */ Function1 e;
    public final /* synthetic */ Function1 f;
    public final /* synthetic */ Function0 g;
    public final /* synthetic */ Function0 h;

    public /* synthetic */ k(com.quizlet.features.folders.addtofolder.data.u uVar, androidx.compose.ui.q qVar, String str, Function1 function1, Function1 function12, Function0 function0, Function0 function02, int i, int i2) {
        this.a = i2;
        this.b = uVar;
        this.c = qVar;
        this.d = str;
        this.e = function1;
        this.f = function12;
        this.g = function0;
        this.h = function02;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1769473);
                Function0 function0 = this.g;
                Function0 function02 = this.h;
                C0.c(this.b, this.c, this.d, this.e, this.f, function0, function02, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1769473);
                Function0 function03 = this.g;
                Function0 function04 = this.h;
                C0.d(this.b, this.c, this.d, this.e, this.f, function03, function04, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}
