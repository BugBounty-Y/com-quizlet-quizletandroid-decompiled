package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.text.AbstractC0503k;
import androidx.compose.foundation.text.C0488f0;
import androidx.compose.foundation.text.C0490g0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.S2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.spans.AztecUnorderedListSpan;
import org.wordpress.aztec.spans.AztecUnorderedListSpanAligned;

/* loaded from: classes2.dex */
public abstract class S2 {
    public static assistantMode.refactored.shims.a a;
    public static assistantMode.utils.h b;

    public static final void a(String answer, InterfaceC0806l interfaceC0806l, int i) {
        String str;
        Intrinsics.checkNotNullParameter(answer, "answer");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(436219860);
        int i2 = (c0814p.f(answer) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            str = answer;
        } else {
            ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
            str = answer;
            b(str, com.quizlet.ui.resources.icons.d.p(c0814p), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.l(), c0814p, i2 & 14);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.recyclerview.step.h(str, i, 2);
        }
    }

    public static final void b(final String str, final androidx.compose.ui.graphics.painter.b bVar, final long j, InterfaceC0806l interfaceC0806l, final int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-524282153);
        int i2 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.h(bVar) ? 32 : 16) | (c0814p.e(j) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            float f = com.quizlet.themes.m.k;
            mVar.e();
            androidx.compose.ui.q qVarG = AbstractC0460p.g(nVar, f, j, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.f));
            mVar.w();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.f;
            mVar.u();
            float f3 = com.quizlet.ui.resources.designsystem.generated.j.g;
            androidx.compose.ui.q qVarV = AbstractC0382e.v(qVarG, f3, f2);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarV);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            U4.a(c0814p);
            com.quizlet.ui.resources.designsystem.generated.h hVar = com.quizlet.ui.resources.designsystem.generated.h.d;
            androidx.compose.material3.D1.a(bVar, null, androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.f), j, c0814p, ((i2 << 3) & 7168) | ((i2 >> 3) & 14) | 48, 0);
            mVar.u();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.o(nVar, f3));
            Q4.b(str, null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 1, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).p, c0814p, i2 & 14, 3072, 57338);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(str, bVar, j, i) { // from class: com.quizlet.features.questiontypes.fitb.ui.a
                public final /* synthetic */ String a;
                public final /* synthetic */ androidx.compose.ui.graphics.painter.b b;
                public final /* synthetic */ long c;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    androidx.compose.ui.graphics.painter.b bVar2 = this.b;
                    long j2 = this.c;
                    S2.b(this.a, bVar2, j2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void c(String answer, InterfaceC0806l interfaceC0806l, int i) {
        String str;
        Intrinsics.checkNotNullParameter(answer, "answer");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-529626951);
        int i2 = (c0814p.f(answer) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            str = answer;
        } else {
            ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
            str = answer;
            b(str, com.quizlet.ui.resources.icons.d.u(c0814p), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.a(), c0814p, i2 & 14);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.recyclerview.step.h(str, i, 1);
        }
    }

    public static final void d(Function1 onInputTextChange, Function1 onDoneClick, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        boolean z;
        InterfaceC0773a0 interfaceC0773a0;
        C0814p c0814p;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(onInputTextChange, "onInputTextChange");
        Intrinsics.checkNotNullParameter(onDoneClick, "onDoneClick");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1042796576);
        int i2 = i | (c0814p2.h(onInputTextChange) ? 4 : 2) | (c0814p2.h(onDoneClick) ? 32 : 16) | 384;
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            qVar2 = qVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.platform.Q0 q0 = (androidx.compose.ui.platform.Q0) c0814p2.j(AbstractC0955m0.n);
            c0814p2.X(1705077304);
            Object objI = c0814p2.I();
            Object obj = C0804k.a;
            if (objI == obj) {
                objI = new androidx.compose.ui.focus.p();
                c0814p2.i0(objI);
            }
            androidx.compose.ui.focus.p pVar = (androidx.compose.ui.focus.p) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(1705079202, c0814p2, false);
            if (objG == obj) {
                objG = androidx.compose.animation.d0.i(c0814p2);
            }
            androidx.compose.foundation.interaction.l lVar = (androidx.compose.foundation.interaction.l) objG;
            Object objG2 = com.google.android.gms.measurement.internal.Z.g(1705081210, c0814p2, false);
            if (objG2 == obj) {
                objG2 = C0776c.z("");
                c0814p2.i0(objG2);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objG2;
            c0814p2.p(false);
            androidx.compose.ui.q qVarK = androidx.compose.ui.focus.a.k(nVar, pVar);
            c0814p2.X(1705086123);
            boolean zF = c0814p2.f(q0);
            Object objI2 = c0814p2.I();
            if (zF || objI2 == obj) {
                objI2 = new com.quizlet.features.infra.folder.create.coursefolder.composable.g(q0, 1);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            androidx.compose.ui.q qVarW = androidx.compose.ui.focus.a.w(qVarK, (Function1) objI2);
            String str = (String) interfaceC0773a02.getValue();
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).m;
            AbstractC0809m0 abstractC0809m0 = com.quizlet.themes.g.a;
            androidx.compose.ui.text.L lB = androidx.compose.ui.text.L.b(l, ((com.quizlet.themes.b) c0814p2.j(abstractC0809m0)).b.e(), 0L, null, null, 0L, 0, 0L, null, 16777214);
            Float fValueOf = Float.valueOf(DefinitionKt.NO_Float_VALUE);
            long j = C0861v.f;
            androidx.compose.ui.graphics.I iT = com.quizlet.shared.usecase.folderstudymaterials.b.t(new Pair[]{new Pair(fValueOf, new C0861v(j)), new Pair(Float.valueOf(0.1f), new C0861v(j)), new Pair(Float.valueOf(0.1f), new C0861v(((com.quizlet.themes.b) c0814p2.j(abstractC0809m0)).b.e())), new Pair(Float.valueOf(0.9f), new C0861v(((com.quizlet.themes.b) c0814p2.j(abstractC0809m0)).b.e())), new Pair(Float.valueOf(0.1f), new C0861v(j)), new Pair(Float.valueOf(1.0f), new C0861v(j))});
            C0490g0 c0490g0 = new C0490g0(1, 7, ContentType.LIVE);
            c0814p2.X(1705114952);
            boolean zF2 = c0814p2.f(q0) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32);
            Object objI3 = c0814p2.I();
            if (zF2 || objI3 == obj) {
                z = true;
                interfaceC0773a0 = interfaceC0773a02;
                Object eVar = new androidx.navigation.internal.e(q0, pVar, onDoneClick, interfaceC0773a0, 6);
                c0814p2.i0(eVar);
                objI3 = eVar;
            } else {
                z = true;
                interfaceC0773a0 = interfaceC0773a02;
            }
            c0814p2.p(false);
            C0488f0 c0488f0 = new C0488f0((Function1) objI3, (Function1) null, (Function1) null, (Function1) null, (Function1) null, 62);
            c0814p2.X(1705089412);
            boolean z2 = (i2 & 14) == 4 ? z : false;
            Object objI4 = c0814p2.I();
            if (z2 || objI4 == obj) {
                objI4 = new com.quizlet.features.flashcards.settings.ui.e(8, interfaceC0773a0, onInputTextChange);
                c0814p2.i0(objI4);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0503k.b(str, (Function1) objI4, qVarW, false, false, lB, c0490g0, c0488f0, true, 0, 0, null, null, null, iT, androidx.compose.runtime.internal.e.e(-816282237, new com.quizlet.assembly.compose.input.m(29, lVar, interfaceC0773a0), c0814p2), c0814p, 102236160, 15896);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 4, onInputTextChange, onDoneClick, qVar2);
        }
    }

    public static final AztecUnorderedListSpan e(int i, EnumC5145a alignmentRendering, C5146b attributes, org.wordpress.aztec.formatting.e listStyle) {
        Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(listStyle, "listStyle");
        int iOrdinal = alignmentRendering.ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                return new AztecUnorderedListSpan(i, attributes, listStyle);
            }
            throw new NoWhenBranchMatchedException();
        }
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(listStyle, "listStyle");
        AztecUnorderedListSpanAligned aztecUnorderedListSpanAligned = new AztecUnorderedListSpanAligned(i, attributes, listStyle);
        aztecUnorderedListSpanAligned.i = null;
        return aztecUnorderedListSpanAligned;
    }
}
