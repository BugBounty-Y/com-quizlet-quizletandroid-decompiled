package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.AbstractC4336b;
import com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.C4340f;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class R5 {
    public static final long a(int i, int i2) {
        return (i2 & 4294967295L) | (i << 32);
    }

    public static final void b(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f data, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(data, "data");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-615151527);
        int i2 = i | (c0814p2.f(data) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16) | (c0814p2.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long j = ((com.quizlet.themes.b) c0814p2.j(b)).f;
            long j2 = ((com.quizlet.themes.b) c0814p2.j(b)).f;
            c0814p2.X(1518687296);
            boolean z = ((i2 & 896) == 256) | ((i2 & 14) == 4);
            Object objI = c0814p2.I();
            if (z || objI == v) {
                objI = new C4340f(function1, data, 0);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(qVarC, null, j, 0L, j2, (Function0) objI, false, null, null, null, androidx.compose.runtime.internal.e.e(-1370355437, new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.h(0, data), c0814p2), c0814p, 0, 970);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.g(data, qVar, function1, i, 0);
        }
    }

    public static final void c(androidx.compose.ui.n nVar, long j, long j2, final androidx.compose.runtime.internal.d content, InterfaceC0806l interfaceC0806l, final int i) {
        Intrinsics.checkNotNullParameter(content, "content");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(605286463);
        if (((i | 150) & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                nVar = androidx.compose.ui.n.b;
                androidx.compose.runtime.B b = com.quizlet.themes.g.a;
                long jC = ((com.quizlet.themes.b) c0814p.j(b)).b.c();
                long jC2 = ((com.quizlet.themes.b) c0814p.j(b)).b.c();
                j = jC;
                j2 = jC2;
            } else {
                c0814p.Q();
            }
            c0814p.q();
            C0776c.a(androidx.compose.foundation.text.selection.q0.a.a(new androidx.compose.foundation.text.selection.p0(j, j2)), androidx.compose.runtime.internal.e.e(100336895, new com.quizlet.features.practicetest.results.i(27, nVar, content), c0814p), c0814p, 56);
        }
        final androidx.compose.ui.n nVar2 = nVar;
        final long j3 = j;
        final long j4 = j2;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(j3, j4, content, i) { // from class: com.quizlet.ui.compose.util.d
                public final /* synthetic */ long b;
                public final /* synthetic */ long c;
                public final /* synthetic */ androidx.compose.runtime.internal.d d;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(3073);
                    androidx.compose.runtime.internal.d dVar = this.d;
                    R5.c(this.a, this.b, this.c, dVar, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void d(androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(344941507);
        if (((i | 6) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(nVar3, 1.0f), "SchoolCourseLoadingResultTestTag");
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(qVarG, null, ((com.quizlet.themes.b) c0814p.j(b)).f, 0L, ((com.quizlet.themes.b) c0814p.j(b)).f, null, false, null, null, null, AbstractC4336b.a, c0814p, 0, 1002);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.changetags.composables.a(nVar2, i, 1);
        }
    }

    public static final void e(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f data, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(data, "data");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(587104474);
        int i2 = i | (c0814p2.f(data) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16) | (c0814p2.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long j = ((com.quizlet.themes.b) c0814p2.j(b)).f;
            long j2 = ((com.quizlet.themes.b) c0814p2.j(b)).f;
            c0814p2.X(-1536518529);
            boolean z = ((i2 & 896) == 256) | ((i2 & 14) == 4);
            Object objI = c0814p2.I();
            if (z || objI == v) {
                objI = new C4340f(function1, data, 1);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(qVar, null, j, 0L, j2, (Function0) objI, false, null, null, null, androidx.compose.runtime.internal.e.e(-21501932, new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.h(1, data), c0814p2), c0814p, (i2 >> 3) & 14, 970);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.g(data, qVar, function1, i, 1);
        }
    }

    public static final long f(long j) {
        return T4.a((int) (j >> 32), (int) (j & 4294967295L));
    }
}
