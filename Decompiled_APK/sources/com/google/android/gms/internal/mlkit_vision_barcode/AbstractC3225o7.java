package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.quizlet.data.model.EnumC4175w;
import com.quizlet.data.model.EssayItem;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.AbstractC4385d;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.o7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3225o7 {
    public static final void a(EssayItem essayItem, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1444477861);
        if ((i & 48) == 0) {
            i2 = (c0814p.h(essayItem) ? 32 : 16) | i;
        } else {
            i2 = i;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i2 & 145) == 144 && c0814p.x()) {
            c0814p.Q();
        } else {
            String str = essayItem.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).n;
            long jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e();
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.material3.Q4.b(str, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7), jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65528);
            c0814p = c0814p;
            mVar.s();
            AbstractC3153g7.d(essayItem, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7), c0814p, (i2 >> 3) & 14, 0);
            com.google.android.gms.internal.mlkit_vision_document_scanner.Y4.b(AbstractC3106b5.d(c0814p, R.string.magic_notes_detail_view_more), androidx.compose.foundation.layout.K0.c(nVar, 1.0f), function0, false, null, null, 0L, 0L, null, null, null, c0814p, (i2 & 896) | 48, 0, 4088);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(essayItem, function0, i, 10);
        }
    }

    public static final void b(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1944965527);
        if ((i & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar, "essayLoading");
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            mVar.u();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.g;
            S5.d(f, AbstractC0382e.y(qVarC2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f2, 7), null, c0814p, 0);
            mVar.q();
            androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            mVar.u();
            S5.d(f, AbstractC0382e.y(qVarC3, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f2, 7), null, c0814p, 0);
            mVar.q();
            androidx.compose.ui.q qVarC4 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            mVar.u();
            S5.d(f, AbstractC0382e.y(qVarC4, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f2, 7), null, c0814p, 0);
            mVar.q();
            androidx.compose.ui.q qVarC5 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            mVar.u();
            S5.d(f, AbstractC0382e.y(qVarC5, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f2, 7), null, c0814p, 0);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 6, qVar);
        }
    }

    public static final void c(EssayItem essayItem, EnumC4175w enumC4175w, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        androidx.compose.ui.q qVar2;
        int i4;
        Function0 function03;
        int i5;
        Function0 function04;
        int i6;
        Function0 function05;
        androidx.compose.ui.q qVar3;
        Function0 function06;
        Function0 function07;
        androidx.compose.ui.q qVar4;
        boolean z;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(920813632);
        if ((i & 6) == 0) {
            i3 = i | (c0814p.h(essayItem) ? 4 : 2);
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p.f(enumC4175w) ? 32 : 16;
        }
        int i7 = i2 & 4;
        if (i7 != 0) {
            i4 = i3 | 384;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i4 = i3 | (c0814p.f(qVar2) ? 256 : 128);
        }
        int i8 = i2 & 8;
        if (i8 != 0) {
            i5 = i4 | 3072;
            function03 = function0;
        } else {
            function03 = function0;
            i5 = i4 | (c0814p.h(function03) ? 2048 : 1024);
        }
        int i9 = i2 & 16;
        if (i9 != 0) {
            i6 = i5 | 24576;
            function04 = function02;
        } else {
            function04 = function02;
            i6 = i5 | (c0814p.h(function04) ? 16384 : 8192);
        }
        if ((i6 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            qVar4 = qVar2;
            function06 = function03;
            function07 = function04;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVar5 = i7 != 0 ? nVar : qVar2;
            androidx.compose.runtime.V v = C0804k.a;
            if (i8 != 0) {
                c0814p.X(1497793239);
                Object objI = c0814p.I();
                if (objI == v) {
                    objI = new com.quizlet.features.emailconfirmation.ui.composables.c(23);
                    c0814p.i0(objI);
                }
                function05 = (Function0) objI;
                c0814p.p(false);
            } else {
                function05 = function03;
            }
            if (i9 != 0) {
                c0814p.X(1497794679);
                Object objI2 = c0814p.I();
                if (objI2 == v) {
                    objI2 = new com.quizlet.features.emailconfirmation.ui.composables.c(24);
                    c0814p.i0(objI2);
                }
                c0814p.p(false);
                function04 = (Function0) objI2;
            }
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i10 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar5);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i10))) {
                android.support.v4.media.session.a.z(i10, c0814p, i10, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p, R.string.magic_notes_sample_essay);
            com.quizlet.themes.m.g.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, 7);
            Function0 function08 = function05;
            Function0 function09 = function04;
            AbstractC3189k7.b(strD, qVarY, null, null, c0814p, 0, 12);
            c0814p = c0814p;
            Object[] objArr = new Object[0];
            c0814p.X(1376127725);
            Object objI3 = c0814p.I();
            if (objI3 == v) {
                objI3 = new com.quizlet.features.emailconfirmation.ui.composables.c(25);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI3, c0814p, 3072, 6);
            boolean z2 = true;
            if (essayItem == null) {
                c0814p.X(-289642772);
                if (enumC4175w == EnumC4175w.PENDING) {
                    c0814p.X(-289587034);
                    qVar3 = qVar5;
                    z = true;
                    androidx.compose.animation.E.f(((Boolean) interfaceC0773a0.getValue()).booleanValue(), null, null, null, null, AbstractC4385d.a, c0814p, 1572870, 30);
                    androidx.compose.animation.E.f(!((Boolean) interfaceC0773a0.getValue()).booleanValue(), null, null, null, null, androidx.compose.runtime.internal.e.e(1127406971, new com.quizlet.assembly.compose.input.g(interfaceC0773a0, function09, 1), c0814p), c0814p, 1572870, 30);
                    c0814p.p(false);
                } else {
                    z = true;
                    qVar3 = qVar5;
                    c0814p.X(-289110688);
                    AbstractC3180j7.a(0, 1, c0814p, null);
                    c0814p.p(false);
                }
                c0814p.p(false);
                z2 = z;
            } else {
                qVar3 = qVar5;
                c0814p.X(-289047510);
                a(essayItem, function08, c0814p, ((i6 >> 3) & 896) | ((i6 << 3) & ContentType.LONG_FORM_ON_DEMAND) | 6);
                c0814p.p(false);
            }
            c0814p.p(z2);
            function06 = function08;
            function07 = function09;
            qVar4 = qVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.h(essayItem, enumC4175w, qVar4, function06, function07, i, i2);
        }
    }

    public static final void d(io.ktor.utils.io.n nVar) {
        Intrinsics.checkNotNullParameter(nVar, "<this>");
        nVar.b(new IOException("Channel was cancelled"));
    }

    public static final String e(int i) {
        return android.support.v4.media.session.a.f(i, "appWidget-");
    }
}
