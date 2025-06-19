package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class g implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ Function1 d;

    public /* synthetic */ g(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f fVar, androidx.compose.ui.q qVar, Function1 function1, int i, int i2) {
        this.a = i2;
        this.b = fVar;
        this.c = qVar;
        this.d = function1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                int iH = C0776c.H(1);
                R5.b(this.b, this.c, this.d, interfaceC0806l, iH);
                break;
            default:
                int iH2 = C0776c.H(1);
                R5.e(this.b, this.c, this.d, interfaceC0806l, iH2);
                break;
        }
        return Unit.a;
    }
}
