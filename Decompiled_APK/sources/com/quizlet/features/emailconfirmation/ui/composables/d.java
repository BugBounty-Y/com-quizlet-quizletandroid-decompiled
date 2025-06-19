package com.quizlet.features.emailconfirmation.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ r b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ float d;
    public final /* synthetic */ Function0 e;
    public final /* synthetic */ Function0 f;
    public final /* synthetic */ Function0 g;

    public /* synthetic */ d(r rVar, androidx.compose.ui.q qVar, float f, Function0 function0, Function0 function02, Function0 function03, int i, int i2) {
        this.a = i2;
        this.b = rVar;
        this.c = qVar;
        this.d = f;
        this.e = function0;
        this.f = function02;
        this.g = function03;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                Function0 function0 = this.f;
                Function0 function02 = this.g;
                q.d(this.b, this.c, this.d, this.e, function0, function02, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                Function0 function03 = this.f;
                Function0 function04 = this.g;
                q.c(this.b, this.c, this.d, this.e, function03, function04, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}
