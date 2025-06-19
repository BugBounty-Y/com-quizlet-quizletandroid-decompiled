package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Build;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.lazy.A;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.geometry.e;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.drawscope.d;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.G;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class M5 {
    public static final void a(androidx.compose.ui.q qVar, androidx.compose.ui.text.input.A a, kotlinx.collections.immutable.b bVar, boolean z, boolean z2, boolean z3, com.quizlet.features.infra.folder.create.data.b bVar2, com.quizlet.features.infra.folder.create.coursefolder.data.m mVar, Function1 function1, Function1 function12, Function1 function13, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function1 function14, Function0 function05, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-539579592);
        int i2 = i | 6 | (c0814p.f(a) ? 32 : 16) | (c0814p.h(bVar) ? 256 : 128) | (c0814p.g(z) ? 2048 : 1024) | (c0814p.g(z2) ? 16384 : 8192) | (c0814p.g(z3) ? 131072 : 65536) | (c0814p.f(bVar2) ? 1048576 : 524288) | (c0814p.f(mVar) ? 8388608 : 4194304) | (c0814p.h(function1) ? 67108864 : 33554432) | (c0814p.h(function12) ? 536870912 : 268435456);
        int i3 = (c0814p.h(function13) ? 4 : 2) | (c0814p.h(function0) ? 32 : 16) | (c0814p.h(function02) ? 256 : 128) | (c0814p.h(function03) ? 2048 : 1024) | (c0814p.h(function04) ? 16384 : 8192) | (c0814p.h(function14) ? 131072 : 65536) | (c0814p.h(function05) ? 1048576 : 524288);
        if ((306783379 & i2) == 306783378 && (i3 & 599187) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                qVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p.Q();
                qVar2 = qVar;
            }
            c0814p.q();
            String strB = O5.b(bVar2, c0814p);
            String strC = O5.c(bVar2, c0814p);
            com.quizlet.themes.m mVar2 = com.quizlet.themes.m.g;
            mVar2.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            mVar2.q();
            androidx.compose.ui.q qVarN = androidx.compose.foundation.layout.K0.n(AbstractC0382e.v(qVar2, f, f), DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.g0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            qVar = qVar2;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarN);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
            com.quizlet.themes.e.a(c0814p).a.getClass();
            AbstractC3691o6.c(null, strB, jG, 0L, com.quizlet.ui.resources.icons.d.u(c0814p), function02, androidx.compose.runtime.internal.e.e(1067111056, new com.quizlet.features.infra.folder.create.coursefolder.composable.d(strC, function0, z3, 0), c0814p), null, c0814p, ((i3 << 9) & 458752) | 1572864, 137);
            int i5 = i3 << 6;
            int i6 = i3 >> 9;
            N5.a(a, function12, function13, function1, null, function03, function04, mVar.b(), mVar, bVar, z && bVar2 == com.quizlet.features.infra.folder.create.data.b.b, z2, function14, function05, c0814p, ((i2 >> 3) & 14) | ((i2 >> 24) & ContentType.LONG_FORM_ON_DEMAND) | (i5 & 896) | ((i2 >> 15) & 7168) | (458752 & i5) | (3670016 & i5) | ((i2 << 3) & 234881024) | ((i2 << 21) & 1879048192), ((i2 >> 9) & ContentType.LONG_FORM_ON_DEMAND) | (i6 & 896) | (i6 & 7168), 16);
            c0814p = c0814p;
            c0814p.p(true);
        }
        androidx.compose.ui.q qVar3 = qVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.composable.c(qVar3, a, bVar, z, z2, z3, bVar2, mVar, function1, function12, function13, function0, function02, function03, function04, function14, function05, i, 0);
        }
    }

    public static androidx.compose.ui.unit.c b() {
        return new androidx.compose.ui.unit.c(1.0f, 1.0f);
    }

    public static final androidx.compose.ui.q c(androidx.compose.ui.q lazyScrollVerticalFadingEdges, final androidx.compose.foundation.lazy.A scrollableState, final float f, final float f2) {
        Intrinsics.checkNotNullParameter(lazyScrollVerticalFadingEdges, "$this$lazyScrollVerticalFadingEdges");
        Intrinsics.checkNotNullParameter(scrollableState, "scrollableState");
        return lazyScrollVerticalFadingEdges.g(androidx.compose.ui.draw.g.g(androidx.compose.ui.graphics.F.q(androidx.compose.ui.n.b, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, false, 65535), new Function1() { // from class: com.quizlet.ui.compose.modifiers.c
            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                G drawWithContent = (G) obj;
                Intrinsics.checkNotNullParameter(drawWithContent, "$this$drawWithContent");
                drawWithContent.b();
                A a = scrollableState;
                float fC0 = drawWithContent.c0(a.b() ? f : 0);
                androidx.compose.ui.graphics.drawscope.b bVar = drawWithContent.a;
                if (fC0 < e.b(bVar.g()) && fC0 > 1.0f) {
                    d.J(drawWithContent, com.quizlet.shared.usecase.folderstudymaterials.b.s(B.j(new C0861v(C0861v.f), new C0861v(C0861v.b)), DefinitionKt.NO_Float_VALUE, fC0, 8), 0L, 0L, DefinitionKt.NO_Float_VALUE, null, 62);
                }
                float fC02 = drawWithContent.c0(a.d() ? f2 : 0);
                if (fC02 < e.b(bVar.g()) && fC02 > 1.0f) {
                    d.J(drawWithContent, com.quizlet.shared.usecase.folderstudymaterials.b.s(B.j(new C0861v(C0861v.b), new C0861v(C0861v.f)), e.b(bVar.g()) - fC02, e.b(bVar.g()), 8), 0L, 0L, DefinitionKt.NO_Float_VALUE, null, 62);
                }
                return Unit.a;
            }
        }));
    }

    public static androidx.compose.ui.q d(androidx.compose.ui.q qVar, androidx.compose.foundation.lazy.A a) {
        com.quizlet.themes.m.g.h();
        float f = com.quizlet.ui.resources.designsystem.generated.h.g;
        return c(qVar, a, f, f);
    }

    public static final androidx.compose.ui.q e(androidx.compose.ui.graphics.I brush) {
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        Intrinsics.checkNotNullParameter(nVar, "<this>");
        Intrinsics.checkNotNullParameter(brush, "brush");
        return androidx.compose.ui.draw.g.g(androidx.compose.ui.graphics.F.q(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, false, 65535), new com.quizlet.ui.compose.modifiers.b(brush, 0));
    }

    public static androidx.compose.ui.q f(androidx.compose.ui.q scrollVerticalFadingEdges, final androidx.compose.foundation.N0 scrollState, final long j, final float f) {
        Intrinsics.checkNotNullParameter(scrollVerticalFadingEdges, "$this$scrollVerticalFadingEdges");
        Intrinsics.checkNotNullParameter(scrollState, "scrollState");
        return Build.VERSION.SDK_INT >= 29 ? androidx.compose.ui.draw.g.g(androidx.compose.ui.graphics.F.p(scrollVerticalFadingEdges, new com.quizlet.qutils.android.f(24)), new Function1() { // from class: com.quizlet.ui.compose.modifiers.a
            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                G drawWithContent = (G) obj;
                Intrinsics.checkNotNullParameter(drawWithContent, "$this$drawWithContent");
                drawWithContent.b();
                long j2 = C0861v.f;
                C0861v c0861v = new C0861v(j2);
                long j3 = j;
                List listJ = B.j(c0861v, new C0861v(j3));
                float fG = scrollState.g();
                d.J(drawWithContent, com.quizlet.shared.usecase.folderstudymaterials.b.s(listJ, fG, Float.min(drawWithContent.c0(f), fG) + fG, 8), 0L, 0L, DefinitionKt.NO_Float_VALUE, null, 62);
                List listJ2 = B.j(new C0861v(j3), new C0861v(j2));
                float fB = (e.b(drawWithContent.a.g()) - r14.f()) + r14.g();
                float fMin = Float.min(drawWithContent.c0(f), r14.f() - r14.g());
                if (fMin != DefinitionKt.NO_Float_VALUE) {
                    d.J(drawWithContent, com.quizlet.shared.usecase.folderstudymaterials.b.s(listJ2, fB - fMin, fB, 8), 0L, 0L, DefinitionKt.NO_Float_VALUE, null, 62);
                }
                return Unit.a;
            }
        }) : scrollVerticalFadingEdges;
    }
}
