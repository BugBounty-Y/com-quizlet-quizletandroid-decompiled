package com.quizlet.learn.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3537t4;
import com.quizlet.learn.data.AbstractC4540e;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ AbstractC4540e b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ g d;
    public final /* synthetic */ q e;
    public final /* synthetic */ Function0 f;
    public final /* synthetic */ Function0 g;
    public final /* synthetic */ Function0 h;
    public final /* synthetic */ int i;

    public /* synthetic */ c(int i, int i2, q qVar, AbstractC4540e abstractC4540e, g gVar, Function0 function0, Function0 function02, Function0 function03, boolean z) {
        this.a = i2;
        this.b = abstractC4540e;
        this.c = z;
        this.d = gVar;
        this.e = qVar;
        this.f = function0;
        this.g = function02;
        this.h = function03;
        this.i = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.i | 1);
                Function0 function0 = this.g;
                Function0 function02 = this.h;
                AbstractC3537t4.f(this.b, this.c, this.d, this.e, this.f, function0, function02, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.i | 1);
                Function0 function03 = this.g;
                Function0 function04 = this.h;
                AbstractC3537t4.e(this.b, this.c, this.d, this.e, this.f, function03, function04, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}
