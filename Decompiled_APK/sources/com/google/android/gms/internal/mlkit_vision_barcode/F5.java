package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import com.google.android.gms.internal.mlkit_vision_barcode.F5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class F5 {
    public static final void a(boolean z, Function1 onCourseFolderToggle, androidx.compose.ui.q qVar, String str, String str2, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(onCourseFolderToggle, "onCourseFolderToggle");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-689775688);
        if (((i | (c0814p2.g(z) ? 4 : 2) | (c0814p2.h(onCourseFolderToggle) ? 32 : 16) | (c0814p2.f(qVar) ? 256 : 128) | (c0814p2.f(str) ? 2048 : 1024) | (c0814p2.f(str2) ? 16384 : 8192) | (c0814p2.h(function0) ? 131072 : 65536) | (c0814p2.h(function02) ? 1048576 : 524288)) & 599187) == 599186 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(AbstractC0382e.p(androidx.compose.animation.H.a(qVar, null, 3), 1), null, 0L, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(1918262206, new com.quizlet.features.infra.folder.create.composables.a(z, function0, str, function02, str2, onCourseFolderToggle), c0814p2), c0814p, 1572864, 950);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.k(z, onCourseFolderToggle, qVar, str, str2, function0, function02, i);
        }
    }

    public static final void b(final androidx.compose.ui.q qVar, final long j, long j2, InterfaceC0806l interfaceC0806l, final int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(95587088);
        if ((((c0814p.f(qVar) ? 4 : 2) | i | (c0814p.e(j) ? 32 : 16) | 128) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).c.getClass();
                j2 = com.quizlet.ui.resources.designsystem.generated.d.T;
            } else {
                c0814p.Q();
            }
            c0814p.q();
            float f = com.quizlet.themes.m.J0;
            androidx.compose.foundation.shape.d dVar = androidx.compose.foundation.shape.e.a;
            androidx.compose.ui.q qVarU = AbstractC0382e.u(AbstractC0460p.g(qVar, f, j, dVar), com.quizlet.themes.m.I0);
            float f2 = com.quizlet.themes.m.F0;
            AbstractC0409s.a(AbstractC0460p.f(androidx.compose.foundation.layout.K0.n(qVarU, f2, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 12), j2, dVar), c0814p, 0);
        }
        final long j3 = j2;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(j, j3, i) { // from class: com.quizlet.ui.compose.f0
                public final /* synthetic */ long b;
                public final /* synthetic */ long c;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    long j4 = this.b;
                    long j5 = this.c;
                    F5.b(this.a, j4, j5, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final long c(long j, float f) {
        return (Float.isNaN(f) || f >= 1.0f) ? j : C0861v.b(j, C0861v.d(j) * f);
    }
}
