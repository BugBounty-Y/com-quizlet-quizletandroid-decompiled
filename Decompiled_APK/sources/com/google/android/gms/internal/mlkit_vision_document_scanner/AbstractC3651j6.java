package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.interaction.l;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.text.L;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3651j6;
import com.quizlet.ui.compose.S;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.j6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3651j6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(final String label, final Function0 onClick, androidx.compose.ui.n nVar, boolean z, androidx.compose.ui.text.L l, int i, int i2, androidx.compose.ui.graphics.painter.b bVar, com.quizlet.ui.compose.S s, com.quizlet.assembly.compose.tags.j jVar, androidx.compose.foundation.interaction.l lVar, InterfaceC0806l interfaceC0806l, final int i3, final int i4) {
        boolean z2;
        int i5;
        androidx.compose.ui.graphics.painter.b bVar2;
        int i6;
        androidx.compose.ui.text.L l2;
        com.quizlet.ui.compose.S s2;
        int i7;
        com.quizlet.assembly.compose.tags.j jVar2;
        final androidx.compose.foundation.interaction.l lVar2;
        androidx.compose.ui.n nVar2;
        int i8;
        androidx.compose.ui.graphics.painter.b bVar3;
        int i9;
        final androidx.compose.ui.text.L l3;
        final boolean z3;
        final com.quizlet.ui.compose.S s3;
        final com.quizlet.assembly.compose.tags.j jVar3;
        final androidx.compose.ui.graphics.painter.b bVar4;
        final int i10;
        final int i11;
        final androidx.compose.ui.n nVar3;
        Intrinsics.checkNotNullParameter(label, "label");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1758365118);
        int i12 = i3 | (c0814p.f(label) ? 4 : 2) | (c0814p.h(onClick) ? 32 : 16);
        int i13 = i12 | 384;
        int i14 = i4 & 8;
        if (i14 != 0) {
            i5 = i12 | 3456;
            z2 = z;
        } else {
            z2 = z;
            i5 = i13 | (c0814p.g(z2) ? 2048 : 1024);
        }
        int i15 = 1777664 | i5;
        int i16 = i4 & 128;
        if (i16 != 0) {
            i6 = i5 | 14360576;
            bVar2 = bVar;
        } else {
            bVar2 = bVar;
            i6 = i15 | (c0814p.h(bVar2) ? 8388608 : 4194304);
        }
        int i17 = i6 | 369098752;
        if ((306783379 & i17) == 306783378 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar;
            i10 = i2;
            s3 = s;
            jVar3 = jVar;
            lVar2 = lVar;
            z3 = z2;
            bVar4 = bVar2;
            l3 = l;
            i11 = i;
        } else {
            c0814p.S();
            if ((i3 & 1) == 0 || c0814p.w()) {
                androidx.compose.ui.n nVar4 = androidx.compose.ui.n.b;
                if (i14 != 0) {
                    z2 = true;
                }
                float f = com.quizlet.assembly.compose.tags.g.a;
                c0814p.X(932748723);
                l2 = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).j;
                c0814p.p(false);
                if (i16 != 0) {
                    bVar2 = null;
                }
                c0814p.X(-1410770760);
                androidx.compose.runtime.B b = com.quizlet.themes.g.a;
                s2 = new com.quizlet.ui.compose.S(((com.quizlet.themes.b) c0814p.j(b)).P, ((com.quizlet.themes.b) c0814p.j(b)).b.f(), ((com.quizlet.themes.b) c0814p.j(b)).b.f(), ((com.quizlet.themes.b) c0814p.j(b)).P, ((com.quizlet.themes.b) c0814p.j(b)).b.b(), ((com.quizlet.themes.b) c0814p.j(b)).b.b());
                c0814p.p(false);
                int i18 = i17 & (-1879105537);
                com.quizlet.assembly.compose.tags.j jVar4 = com.quizlet.assembly.compose.tags.j.b;
                c0814p.X(-1497289003);
                Object objI = c0814p.I();
                if (objI == C0804k.a) {
                    objI = androidx.compose.animation.d0.i(c0814p);
                }
                c0814p.p(false);
                i7 = i18;
                jVar2 = jVar4;
                lVar2 = (androidx.compose.foundation.interaction.l) objI;
                nVar2 = nVar4;
                i8 = 1;
                bVar3 = bVar2;
                i9 = 2;
            } else {
                c0814p.Q();
                int i19 = i17 & (-1879105537);
                nVar2 = nVar;
                i8 = i;
                s2 = s;
                jVar2 = jVar;
                lVar2 = lVar;
                bVar3 = bVar2;
                i7 = i19;
                l2 = l;
                i9 = i2;
            }
            c0814p.q();
            androidx.compose.ui.q qVarQ = androidx.compose.foundation.layout.K0.q(nVar2, DefinitionKt.NO_Float_VALUE, com.quizlet.assembly.compose.tags.g.a, 1);
            c0814p.X(-1497275457);
            androidx.compose.runtime.internal.d dVarE = bVar3 == null ? null : androidx.compose.runtime.internal.e.e(1711546040, new com.quizlet.assembly.compose.input.j(bVar3, 2), c0814p);
            c0814p.p(false);
            com.quizlet.themes.m.g.b();
            int i20 = i7;
            int i21 = i8;
            androidx.compose.ui.n nVar5 = nVar2;
            boolean z4 = z2;
            l3 = l2;
            com.quizlet.ui.compose.S s4 = s2;
            com.quizlet.ui.compose.c0.d(onClick, z4, androidx.compose.runtime.internal.e.e(1353653621, new com.quizlet.assembly.compose.tags.d(label, i9, i8, 1), c0814p), l3, dVarE, s4, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.j), com.quizlet.assembly.compose.tags.g.b(jVar2), com.quizlet.assembly.compose.tags.g.c(jVar2), lVar2, qVarQ, c0814p, ((i20 >> 3) & 14) | 384 | ((i20 >> 6) & ContentType.LONG_FORM_ON_DEMAND) | 12582912, 6);
            z3 = z4;
            s3 = s4;
            jVar3 = jVar2;
            bVar4 = bVar3;
            i10 = i9;
            i11 = i21;
            nVar3 = nVar5;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(label, onClick, nVar3, z3, l3, i11, i10, bVar4, s3, jVar3, lVar2, i3, i4) { // from class: com.quizlet.assembly.compose.tags.i
                public final /* synthetic */ String a;
                public final /* synthetic */ Function0 b;
                public final /* synthetic */ n c;
                public final /* synthetic */ boolean d;
                public final /* synthetic */ L e;
                public final /* synthetic */ int f;
                public final /* synthetic */ int g;
                public final /* synthetic */ androidx.compose.ui.graphics.painter.b h;
                public final /* synthetic */ S i;
                public final /* synthetic */ j j;
                public final /* synthetic */ l k;
                public final /* synthetic */ int l;

                {
                    this.l = i4;
                }

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    l lVar3 = this.k;
                    AbstractC3651j6.a(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, lVar3, (InterfaceC0806l) obj, iH, this.l);
                    return Unit.a;
                }
            };
        }
    }
}
