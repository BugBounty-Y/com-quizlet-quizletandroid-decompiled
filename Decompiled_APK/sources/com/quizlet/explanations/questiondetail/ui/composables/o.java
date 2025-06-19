package com.quizlet.explanations.questiondetail.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3269u0;
import com.google.android.gms.internal.mlkit_vision_barcode.C5;
import com.google.android.gms.internal.mlkit_vision_barcode.S4;
import com.google.android.gms.internal.mlkit_vision_barcode.V4;
import com.google.android.gms.internal.mlkit_vision_common.A4;
import com.google.android.gms.internal.mlkit_vision_common.N3;
import com.google.android.gms.internal.mlkit_vision_common.W3;
import com.google.android.gms.internal.mlkit_vision_common.z4;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.data.model.m2;
import com.quizlet.features.folders.data.Q0;
import com.quizlet.ui.compose.C4815h;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final /* synthetic */ class o implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ o(com.quizlet.learn.data.onboarding.c cVar, boolean z, Function1 function1, androidx.compose.ui.q qVar, int i) {
        this.a = 7;
        this.d = cVar;
        this.c = z;
        this.e = function1;
        this.b = qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                boolean z = this.c;
                Function2 function2 = (Function2) this.e;
                com.google.common.util.concurrent.a.a((kotlinx.collections.immutable.b) this.d, (androidx.compose.ui.q) this.b, z, function2, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                boolean z2 = this.c;
                Function1 function1 = (Function1) this.e;
                S4.a((Q0) this.d, (androidx.compose.ui.q) this.b, z2, function1, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                Function0 function0 = (Function0) this.b;
                androidx.compose.ui.n nVar = (androidx.compose.ui.n) this.e;
                V4.e(this.c, (Function0) this.d, function0, nVar, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(1);
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) this.b;
                Function0 function02 = (Function0) this.e;
                com.quizlet.features.settings.composables.changetheme.a.b(this.c, (String) this.d, qVar, function02, (InterfaceC0806l) obj, iH4);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(1);
                Function0 function03 = (Function0) this.b;
                Function0 function04 = (Function0) this.e;
                N3.c((Function0) this.d, this.c, function03, function04, (InterfaceC0806l) obj, iH5);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(513);
                x xVar = (x) this.b;
                Function1 function12 = (Function1) this.e;
                W3.a((m2) this.d, this.c, xVar, function12, (InterfaceC0806l) obj, iH6);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(3121);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.e;
                z4.b((com.quizlet.learn.data.onboarding.d) this.d, this.c, (Function1) this.b, dVar, (InterfaceC0806l) obj, iH7);
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(49);
                Function1 function13 = (Function1) this.e;
                androidx.compose.ui.q qVar2 = (androidx.compose.ui.q) this.b;
                A4.a((com.quizlet.learn.data.onboarding.c) this.d, this.c, function13, qVar2, (InterfaceC0806l) obj, iH8);
                break;
            case 8:
                ((Integer) obj2).getClass();
                int iH9 = C0776c.H(1);
                boolean z3 = this.c;
                androidx.compose.ui.focus.h hVar = (androidx.compose.ui.focus.h) this.e;
                AbstractC3269u0.d((com.quizlet.search.viewmodels.p) this.d, (androidx.compose.ui.q) this.b, z3, hVar, (InterfaceC0806l) obj, iH9);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH10 = C0776c.H(1);
                Function0 function05 = (Function0) this.b;
                androidx.compose.ui.n nVar2 = (androidx.compose.ui.n) this.e;
                C5.c((C4815h) this.d, this.c, function05, nVar2, (InterfaceC0806l) obj, iH10);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ o(Object obj, androidx.compose.ui.q qVar, boolean z, Object obj2, int i, int i2) {
        this.a = i2;
        this.d = obj;
        this.b = qVar;
        this.c = z;
        this.e = obj2;
    }

    public /* synthetic */ o(Object obj, boolean z, Object obj2, Object obj3, int i, int i2) {
        this.a = i2;
        this.d = obj;
        this.c = z;
        this.b = obj2;
        this.e = obj3;
    }

    public /* synthetic */ o(boolean z, Object obj, Object obj2, Object obj3, int i, int i2) {
        this.a = i2;
        this.c = z;
        this.d = obj;
        this.b = obj2;
        this.e = obj3;
    }
}
