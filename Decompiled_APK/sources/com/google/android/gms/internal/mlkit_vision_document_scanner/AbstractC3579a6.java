package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.a6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3579a6 {
    public static final void a(kotlinx.collections.immutable.b subjectCategories, androidx.compose.ui.n nVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(subjectCategories, "subjectCategories");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1848930874);
        int i2 = i | (c0814p2.f(subjectCategories) ? 4 : 2) | 48 | (c0814p2.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.s();
            mVar.s();
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(AbstractC0382e.y(nVar3, f, DefinitionKt.NO_Float_VALUE, f, f, 2), 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, 0);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, qVarC);
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
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h);
            }
            C0776c.E(c0814p2, qVarC2, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p2, R.string.empty_home_subject_title);
            Locale locale = Locale.ROOT;
            String lowerCase = strD.toLowerCase(locale);
            Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
            if (lowerCase.length() > 0) {
                StringBuilder sb = new StringBuilder();
                String strValueOf = String.valueOf(lowerCase.charAt(0));
                Intrinsics.e(strValueOf, "null cannot be cast to non-null type java.lang.String");
                String upperCase = strValueOf.toUpperCase(locale);
                Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
                sb.append((Object) upperCase);
                String strSubstring = lowerCase.substring(1);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                sb.append(strSubstring);
                lowerCase = sb.toString();
            }
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).i;
            long jE = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e();
            mVar.p();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.j;
            mVar.s();
            nVar2 = nVar3;
            androidx.compose.material3.Q4.b(lowerCase, AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, f, 5), jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p2, 0, 0, 65528);
            c0814p = c0814p2;
            b(subjectCategories, function1, c0814p, ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | (i2 & 14));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(i, 0, subjectCategories, nVar2, function1);
        }
    }

    public static final void b(kotlinx.collections.immutable.b bVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(559037358);
        int i2 = (i & 6) == 0 ? (c0814p.f(bVar) ? 4 : 2) | i : i;
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m.g.s();
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0392jG, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(-1792157411);
            Iterator it2 = CollectionsKt.E(bVar, 3).iterator();
            while (it2.hasNext()) {
                List list = (List) it2.next();
                C0380d c0380d2 = AbstractC0398m.a;
                com.quizlet.themes.m.g.s();
                androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h), androidx.compose.ui.b.j, c0814p, 0);
                int i4 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
                androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, nVar);
                InterfaceC0915k.D0.getClass();
                C0913i c0913i2 = C0914j.b;
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i2);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, g0B, C0914j.f);
                C0776c.E(c0814p, interfaceC0803j0L2, C0914j.e);
                C0912h c0912h2 = C0914j.g;
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                    android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h2);
                }
                C0776c.E(c0814p, qVarC2, C0914j.d);
                androidx.compose.foundation.layout.I0 i0 = androidx.compose.foundation.layout.I0.a;
                c0814p.X(-161188684);
                Iterator it3 = list.iterator();
                while (it3.hasNext()) {
                    c((com.quizlet.generated.enums.I1) it3.next(), function1, i0.a(nVar, 1.0f, true), c0814p, i2 & ContentType.LONG_FORM_ON_DEMAND);
                }
                c0814p.p(false);
                c0814p.X(-161177656);
                for (int size = list.size(); size < 3; size++) {
                    AbstractC0382e.f(c0814p, i0.a(nVar, 1.0f, true));
                }
                c0814p.p(false);
                c0814p.p(true);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(bVar, function1, i, 25);
        }
    }

    public static final void c(final com.quizlet.generated.enums.I1 i1, final Function1 function1, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1308756840);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(i1) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(function1) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(qVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            String strD = AbstractC3106b5.d(c0814p2, com.google.android.gms.internal.mlkit_vision_common.H3.a(i1));
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.n, c0814p2, 48);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVar);
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
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jN = ((com.quizlet.themes.b) c0814p2.j(b)).b.n();
            c0814p2.X(1473277723);
            int i4 = i2 & ContentType.LONG_FORM_ON_DEMAND;
            int i5 = i2 & 14;
            boolean z = (i4 == 32) | (i5 == 4);
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                final int i6 = 0;
                objI = new Function0() { // from class: com.quizlet.quizletandroid.ui.startpage.nav2.composables.g
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i6) {
                            case 0:
                                function1.invoke(i1);
                                break;
                            default:
                                function1.invoke(i1);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            R4.a(null, null, jN, 0L, 0L, (Function0) objI, false, null, null, null, androidx.compose.runtime.internal.e.e(1723523272, new com.quizlet.features.practicetest.results.i(20, i1, strD), c0814p2), c0814p2, 0, 987);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.b)).k;
            long jE = ((com.quizlet.themes.b) c0814p2.j(b)).b.e();
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.u();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            c0814p2.X(1473305371);
            boolean z2 = (i5 == 4) | (i4 == 32);
            Object objI2 = c0814p2.I();
            if (z2 || objI2 == v) {
                final int i7 = 1;
                objI2 = new Function0() { // from class: com.quizlet.quizletandroid.ui.startpage.nav2.composables.g
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i7) {
                            case 0:
                                function1.invoke(i1);
                                break;
                            default:
                                function1.invoke(i1);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            androidx.compose.material3.Q4.b(strD, AbstractC0460p.l(qVarY, false, null, (Function0) objI2, 7), jE, 0L, null, 0L, null, 0L, 2, false, 1, 0, null, l, c0814p2, 0, 3120, 55288);
            c0814p = c0814p2;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 18, qVar, (Object) i1, (Object) function1);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:100:0x01ac  */
    /* JADX WARN: Removed duplicated region for block: B:102:0x01b0  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x025d  */
    /* JADX WARN: Removed duplicated region for block: B:141:0x0316  */
    /* JADX WARN: Removed duplicated region for block: B:143:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:47:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x009b  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00bd  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00dc  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00de  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00e1  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x00e7  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0135  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0139  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x015f  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x0175  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x01a5 A[ADDED_TO_REGION] */
    /* JADX WARN: Type inference failed for: r13v26 */
    /* JADX WARN: Type inference failed for: r13v27 */
    /* JADX WARN: Type inference failed for: r13v8, types: [androidx.compose.runtime.internal.d] */
    /* JADX WARN: Type inference failed for: r24v0, types: [java.lang.Object, kotlin.jvm.functions.c] */
    /* JADX WARN: Type inference failed for: r25v0, types: [androidx.compose.runtime.internal.d, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r26v0, types: [androidx.compose.runtime.internal.d, java.lang.Object] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(androidx.compose.ui.q r23, final kotlin.jvm.functions.c r24, final androidx.compose.runtime.internal.d r25, final androidx.compose.runtime.internal.d r26, androidx.compose.runtime.internal.d r27, int r28, boolean r29, androidx.compose.runtime.InterfaceC0806l r30, final int r31, final int r32) {
        /*
            Method dump skipped, instructions count: 806
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3579a6.d(androidx.compose.ui.q, kotlin.jvm.functions.c, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, int, boolean, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0042  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0047  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x005d  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0062  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0078  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x007d  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0094  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00b2  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00cf  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00d1  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00d4  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00d7  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x00da  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x00dd  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0104  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0136  */
    /* JADX WARN: Removed duplicated region for block: B:89:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void e(java.lang.String r18, androidx.compose.ui.q r19, java.lang.String r20, androidx.compose.runtime.internal.d r21, androidx.compose.runtime.internal.d r22, int r23, androidx.compose.runtime.InterfaceC0806l r24, int r25, int r26) {
        /*
            Method dump skipped, instructions count: 320
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3579a6.e(java.lang.String, androidx.compose.ui.q, java.lang.String, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, int, androidx.compose.runtime.l, int, int):void");
    }
}
