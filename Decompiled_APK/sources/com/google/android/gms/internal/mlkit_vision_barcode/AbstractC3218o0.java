package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.C0555x;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.material3.AbstractC0590b0;
import androidx.compose.material3.AbstractC0669k0;
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
import com.braze.C1483i;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.o0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3218o0 {
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v27 */
    /* JADX WARN: Type inference failed for: r0v28, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r0v31 */
    public static final void a(androidx.compose.ui.graphics.painter.b painter, int i, int i2, boolean z, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i3) {
        ?? r0;
        androidx.compose.ui.q qVar2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(painter, "painter");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1700762653);
        int i4 = i3 | (c0814p2.h(painter) ? 4 : 2) | (c0814p2.d(i) ? 32 : 16) | (c0814p2.d(i2) ? 256 : 128) | (c0814p2.g(z) ? 2048 : 1024) | 24576 | (c0814p2.h(function1) ? 131072 : 65536);
        if ((74899 & i4) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            qVar2 = qVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            Object obj = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p2.X(739285170);
            int i5 = i4 & 7168;
            boolean z2 = i5 == 2048;
            Object objI = c0814p2.I();
            if (z2 || objI == obj) {
                objI = new C1483i(z, 9);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p2, 0, 6);
            Boolean boolValueOf = Boolean.valueOf(z);
            c0814p2.X(739287090);
            boolean zF = c0814p2.f(interfaceC0773a0) | (i5 == 2048);
            Object objI2 = c0814p2.I();
            if (zF || objI2 == obj) {
                objI2 = new com.quizlet.features.flashcards.settings.ui.g(z, interfaceC0773a0, null);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            C0776c.f(c0814p2, boolValueOf, (Function2) objI2);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.n, c0814p2, 48);
            int i6 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, nVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, bA, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p2, i6, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.j();
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.i), "toggle");
            boolean zBooleanValue = ((Boolean) interfaceC0773a0.getValue()).booleanValue();
            androidx.compose.foundation.shape.d dVar = androidx.compose.foundation.shape.e.a;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jN = ((com.quizlet.themes.b) c0814p2.j(b)).b.n();
            long jN2 = ((com.quizlet.themes.b) c0814p2.j(b)).b.n();
            long jF = ((com.quizlet.themes.b) c0814p2.j(b)).b.f();
            long j = ((com.quizlet.themes.b) c0814p2.j(b)).e;
            long j2 = C0861v.g;
            long jB = C0861v.b(jF, 0.38f);
            androidx.compose.material3.Z z3 = (androidx.compose.material3.Z) c0814p2.j(AbstractC0590b0.a);
            long j3 = ((C0861v) c0814p2.j(AbstractC0669k0.a)).a;
            z3.getClass();
            long j4 = C0861v.f;
            long jB2 = C0861v.b(j3, 0.38f);
            float f = androidx.compose.material3.tokens.s.a;
            androidx.compose.material3.E1 e1 = new androidx.compose.material3.E1(jN != 16 ? jN : j4, jF != 16 ? jF : j3, j2 != 16 ? j2 : j4, jB != 16 ? jB : jB2, jN2 != 16 ? jN2 : AbstractC0590b0.c(z3, 6), j != 16 ? j : AbstractC0590b0.a(z3, AbstractC0590b0.c(z3, 6)));
            C0555x c0555xA = AbstractC0460p.a(((com.quizlet.themes.b) c0814p2.j(b)).t(), com.quizlet.themes.m.l);
            c0814p2.X(411807938);
            boolean zF2 = c0814p2.f(interfaceC0773a0) | ((i4 & 458752) == 131072);
            Object objI3 = c0814p2.I();
            if (zF2 || objI3 == obj) {
                r0 = 0;
                objI3 = new com.quizlet.features.flashcards.settings.ui.e(0, interfaceC0773a0, function1);
                c0814p2.i0(objI3);
            } else {
                r0 = 0;
            }
            c0814p2.p(r0);
            androidx.compose.material3.Z1.k(zBooleanValue, (Function1) objI3, qVarG, false, dVar, e1, c0555xA, androidx.compose.runtime.internal.e.e(137429737, new com.quizlet.features.flashcards.settings.ui.h(i, painter, r0), c0814p2), c0814p2, 100663296);
            mVar.s();
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, i2), AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), ((com.quizlet.themes.b) c0814p2.j(b)).b.f(), 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).l, c0814p2, 0, 0, 65016);
            C0814p c0814p3 = c0814p2;
            c0814p3.p(true);
            qVar2 = nVar;
            c0814p = c0814p3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.settings.ui.f(painter, i, i2, z, qVar2, function1, i3);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:110:0x01cf  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x022a  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x022d  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x023f  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x0330  */
    /* JADX WARN: Removed duplicated region for block: B:133:0x033e  */
    /* JADX WARN: Removed duplicated region for block: B:137:0x039f  */
    /* JADX WARN: Removed duplicated region for block: B:139:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0055  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x005a  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x008c  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00bd  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00ec  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00ef  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00f5  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x0100  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0103  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x011f  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x0122  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x013e  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0141  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x0175  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x0189  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x019e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(androidx.compose.ui.n r71, java.lang.String r72, boolean r73, androidx.compose.ui.focus.h r74, kotlin.jvm.functions.Function1 r75, kotlin.jvm.functions.Function0 r76, kotlin.jvm.functions.Function1 r77, androidx.compose.runtime.InterfaceC0806l r78, int r79, int r80) {
        /*
            Method dump skipped, instructions count: 939
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3218o0.b(androidx.compose.ui.n, java.lang.String, boolean, androidx.compose.ui.focus.h, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    public static androidx.compose.foundation.text.modifiers.b c(androidx.compose.foundation.text.modifiers.b bVar, androidx.compose.ui.unit.k kVar, androidx.compose.ui.text.L l, androidx.compose.ui.unit.b bVar2, androidx.compose.ui.text.font.i iVar) {
        if (bVar != null && kVar == bVar.a && Intrinsics.b(l, bVar.b) && bVar2.a() == bVar.c.a && iVar == bVar.d) {
            return bVar;
        }
        androidx.compose.foundation.text.modifiers.b bVar3 = androidx.compose.foundation.text.modifiers.b.h;
        if (bVar3 != null && kVar == bVar3.a && Intrinsics.b(l, bVar3.b) && bVar2.a() == bVar3.c.a && iVar == bVar3.d) {
            return bVar3;
        }
        androidx.compose.foundation.text.modifiers.b bVar4 = new androidx.compose.foundation.text.modifiers.b(kVar, AbstractC3214n5.c(l, kVar), new androidx.compose.ui.unit.c(bVar2.a(), bVar2.Z()), iVar);
        androidx.compose.foundation.text.modifiers.b.h = bVar4;
        return bVar4;
    }
}
