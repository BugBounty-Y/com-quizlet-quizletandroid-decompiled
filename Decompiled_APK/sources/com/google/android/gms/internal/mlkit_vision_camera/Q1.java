package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.navigation.C1265a;
import androidx.navigation.compose.C1278k;
import androidx.navigation.compose.C1280m;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3137f0;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Home;
import kotlin.Pair;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Q1 {
    public static final void a(androidx.navigation.H h, androidx.compose.ui.n nVar, androidx.compose.ui.i iVar, Function1 function1, Function1 function12, Function1 function13, Function1 function14, Function1 function15, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar2;
        androidx.compose.ui.i iVar2;
        Function1 function16;
        Function1 function17;
        int i3;
        char c;
        Function1 function18;
        Function1 function19;
        Function1 function110;
        Function1 function111;
        androidx.compose.ui.i iVar3;
        Function1 function112;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1840250294);
        if ((i & 6) == 0) {
            i2 = i | (c0814p.h(h) ? 4 : 2);
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f("learn_settings") ? 32 : 16;
        }
        int i4 = 1797504 | i2;
        if ((i & 12582912) == 0) {
            i4 = 5991808 | i2;
        }
        if ((i & 100663296) == 0) {
            i4 |= 33554432;
        }
        int i5 = 805306368 | i4;
        char c2 = c0814p.h(function15) ? (char) 4 : (char) 2;
        if ((306783379 & i5) == 306783378 && (c2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
            iVar3 = iVar;
            function18 = function1;
            function112 = function12;
            function111 = function13;
            function110 = function14;
        } else {
            c0814p.S();
            int i6 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i6 == 0 || c0814p.w()) {
                nVar2 = androidx.compose.ui.n.b;
                iVar2 = androidx.compose.ui.b.a;
                Object objI = c0814p.I();
                if (objI == v) {
                    objI = new C1265a(12);
                    c0814p.i0(objI);
                }
                function16 = (Function1) objI;
                Object objI2 = c0814p.I();
                if (objI2 == v) {
                    objI2 = new C1265a(15);
                    c0814p.i0(objI2);
                }
                function17 = (Function1) objI2;
                i3 = i5 & (-264241153);
                c = c2;
                function18 = function16;
                function19 = function17;
            } else {
                c0814p.Q();
                nVar2 = nVar;
                iVar2 = iVar;
                function17 = function12;
                function16 = function13;
                i3 = i5 & (-264241153);
                c = c2;
                function18 = function1;
                function19 = function14;
            }
            c0814p.q();
            boolean z = ((i3 & 57344) == 16384) | ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((c & 14) == 4);
            Object objI3 = c0814p.I();
            if (z || objI3 == v) {
                androidx.navigation.E e = new androidx.navigation.E(h.b.s, "learn_settings");
                function15.invoke(e);
                objI3 = e.a();
                c0814p.i0(objI3);
            }
            androidx.navigation.D d = (androidx.navigation.D) objI3;
            int i7 = i3 >> 3;
            int i8 = (i3 & 8078) | (i7 & 57344) | (458752 & i7) | (i7 & 234881024);
            function110 = function19;
            function111 = function16;
            iVar3 = iVar2;
            function112 = function17;
            b(h, d, nVar2, iVar3, function18, function112, function111, function110, null, c0814p, i8, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.E(h, nVar2, iVar3, function18, function112, function111, function110, function15, i, 0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:106:0x014c  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x0153  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x0166  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x016a  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x0180  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x0188  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x018e  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x0195  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x01ac  */
    /* JADX WARN: Removed duplicated region for block: B:230:0x0450  */
    /* JADX WARN: Removed duplicated region for block: B:231:0x0457  */
    /* JADX WARN: Removed duplicated region for block: B:234:0x046d  */
    /* JADX WARN: Removed duplicated region for block: B:235:0x0474  */
    /* JADX WARN: Removed duplicated region for block: B:238:0x0479  */
    /* JADX WARN: Removed duplicated region for block: B:245:0x0493  */
    /* JADX WARN: Removed duplicated region for block: B:247:0x04b9  */
    /* JADX WARN: Removed duplicated region for block: B:253:0x04da  */
    /* JADX WARN: Removed duplicated region for block: B:255:0x04dd  */
    /* JADX WARN: Removed duplicated region for block: B:496:0x0bac  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:500:0x0bc7  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0094  */
    /* JADX WARN: Removed duplicated region for block: B:553:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00ad  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00cb  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x00e1  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00ed  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x011e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(final androidx.navigation.H r42, final androidx.navigation.D r43, final androidx.compose.ui.q r44, androidx.compose.ui.d r45, kotlin.jvm.functions.Function1 r46, kotlin.jvm.functions.Function1 r47, kotlin.jvm.functions.Function1 r48, kotlin.jvm.functions.Function1 r49, kotlin.jvm.functions.Function1 r50, androidx.compose.runtime.InterfaceC0806l r51, final int r52, final int r53) {
        /*
            Method dump skipped, instructions count: 3023
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.Q1.b(androidx.navigation.H, androidx.navigation.D, androidx.compose.ui.q, androidx.compose.ui.d, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    public static final void c(androidx.navigation.H h, GlobalNavSuiteItem$Home globalNavSuiteItem$Home, androidx.compose.ui.n nVar, androidx.compose.ui.i iVar, kotlin.collections.L l, Function1 function1, Function1 function12, Function1 function13, Function1 function14, Function1 function15, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function1 function16;
        int i3;
        androidx.compose.ui.i iVar2;
        int i4;
        androidx.compose.ui.n nVar2;
        Function1 function17;
        Function1 function18;
        kotlin.collections.L l2;
        int i5;
        Function1 function19;
        Function1 function110;
        C0814p c0814p;
        Function1 function111;
        Function1 function112;
        androidx.compose.ui.i iVar3;
        Function1 function113;
        kotlin.collections.L l3;
        androidx.compose.ui.n nVar3;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1476019057);
        if ((i & 6) == 0) {
            i2 = i | (c0814p2.h(h) ? 4 : 2);
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(globalNavSuiteItem$Home) ? 32 : 16;
        }
        int i6 = 14380416 | i2;
        if ((i & 100663296) == 0) {
            i6 = 47934848 | i2;
        }
        if ((i & 805306368) == 0) {
            i6 |= 268435456;
        }
        int i7 = (c0814p2.h(function15) ? ' ' : (char) 16) | 6;
        if ((306783379 & i6) == 306783378 && (i7 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            nVar3 = nVar;
            iVar3 = iVar;
            l3 = l;
            function111 = function1;
            function113 = function12;
            function110 = function13;
            c0814p = c0814p2;
            function112 = function14;
        } else {
            c0814p2.S();
            int i8 = i & 1;
            Object obj = C0804k.a;
            if (i8 == 0 || c0814p2.w()) {
                androidx.compose.ui.n nVar4 = androidx.compose.ui.n.b;
                androidx.compose.ui.i iVar4 = androidx.compose.ui.b.a;
                kotlin.collections.L lC = kotlin.collections.V.c();
                Object objI = c0814p2.I();
                if (objI == obj) {
                    objI = new C1265a(13);
                    c0814p2.i0(objI);
                }
                Function1 function114 = (Function1) objI;
                Object objI2 = c0814p2.I();
                if (objI2 == obj) {
                    objI2 = new C1265a(14);
                    c0814p2.i0(objI2);
                }
                function16 = (Function1) objI2;
                i3 = i7;
                iVar2 = iVar4;
                i4 = i6 & (-2113929217);
                nVar2 = nVar4;
                function17 = function114;
                function18 = function17;
                l2 = lC;
                i5 = 100663296;
                function19 = function16;
            } else {
                c0814p2.Q();
                l2 = l;
                function18 = function13;
                function16 = function14;
                i4 = i6 & (-2113929217);
                i3 = i7;
                i5 = 100663296;
                nVar2 = nVar;
                iVar2 = iVar;
                function17 = function1;
                function19 = function12;
            }
            c0814p2.q();
            int i9 = i5;
            boolean zF = ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | c0814p2.f(null) | c0814p2.f(globalNavSuiteItem$Home);
            Object objI3 = c0814p2.I();
            if (zF || objI3 == obj) {
                androidx.navigation.E e = new androidx.navigation.E(h.b.s, globalNavSuiteItem$Home, l2);
                function15.invoke(e);
                objI3 = e.a();
                c0814p2.i0(objI3);
            }
            int i10 = i4 >> 6;
            int i11 = (i4 & 8078) | (57344 & i10) | (i10 & 458752) | i9;
            Function1 function115 = function17;
            Function1 function116 = function16;
            b(h, (androidx.navigation.D) objI3, nVar2, iVar2, function115, function19, function18, function116, null, c0814p2, i11, 0);
            function110 = function18;
            c0814p = c0814p2;
            function111 = function115;
            function112 = function116;
            iVar3 = iVar2;
            function113 = function19;
            l3 = l2;
            nVar3 = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.D(h, globalNavSuiteItem$Home, nVar3, iVar3, l3, function111, function113, function110, function112, function15, i);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0054  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0071  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0076  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x0081  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0088  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x009c  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00c7  */
    /* JADX WARN: Removed duplicated region for block: B:65:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(androidx.navigation.H r15, java.lang.String r16, androidx.compose.ui.q r17, kotlin.jvm.functions.Function1 r18, androidx.compose.runtime.InterfaceC0806l r19, int r20, int r21) {
        /*
            Method dump skipped, instructions count: 214
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.Q1.d(androidx.navigation.H, java.lang.String, androidx.compose.ui.q, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    public static final void e(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function1 onRowClick, kotlinx.collections.immutable.e questionList) {
        Intrinsics.checkNotNullParameter(questionList, "questionList");
        Intrinsics.checkNotNullParameter(onRowClick, "onRowClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1651020858);
        int i2 = (c0814p.f(questionList) ? 4 : 2) | i | (c0814p.h(onRowClick) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m.g.u();
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.g);
            c0814p.X(-1369020084);
            boolean z = ((i2 & 14) == 4) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32);
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new androidx.lifecycle.u0(25, (Object) questionList, (Object) onRowClick);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3137f0.a(qVar, null, null, c0392jG, null, null, false, (Function1) objI, c0814p, (i2 >> 6) & 14, 238);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.home.composables.sections.c(questionList, onRowClick, qVar, i);
        }
    }

    public static final void f(com.quizlet.features.practicetest.common.data.i iVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(346727309);
        if ((((c0814p.f(iVar) ? 4 : 2) | i | (c0814p.h(function1) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.themes.m.g.u();
            androidx.compose.material3.Z1.c(null, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.j.g), null, null, null, androidx.compose.runtime.internal.e.e(1852324351, new com.quizlet.assembly.compose.input.m(23, iVar, function1), c0814p), c0814p, 196608, 29);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(iVar, function1, i, 25);
        }
    }

    public static final void g(com.quizlet.features.practicetest.common.data.j jVar, InterfaceC0806l interfaceC0806l, int i) {
        Pair pair;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-236140747);
        if ((((c0814p.f(jVar) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            int iOrdinal = jVar.ordinal();
            if (iOrdinal == 0) {
                c0814p.X(1724928925);
                pair = new Pair(null, new C0861v(((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f()));
                c0814p.p(false);
            } else if (iOrdinal == 1) {
                c0814p.X(1724932624);
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                c0814p.X(-621765234);
                androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_sys_circled_check, c0814p, 0);
                c0814p.p(false);
                pair = new Pair(bVarA, new C0861v(((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f()));
                c0814p.p(false);
            } else if (iOrdinal == 2) {
                c0814p.X(1724937892);
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                c0814p.X(292880656);
                androidx.compose.ui.graphics.painter.b bVarA2 = Z4.a(R.drawable.ic_sys_block, c0814p, 0);
                c0814p.p(false);
                pair = new Pair(bVarA2, new C0861v(((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.b()));
                c0814p.p(false);
            } else if (iOrdinal == 3) {
                c0814p.X(1724942800);
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                pair = new Pair(com.quizlet.ui.resources.icons.d.s(c0814p), new C0861v(((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.l()));
                c0814p.p(false);
            } else if (iOrdinal == 4) {
                c0814p.X(1724948152);
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                pair = new Pair(com.quizlet.ui.resources.icons.d.t(c0814p), new C0861v(((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).Q0));
                c0814p.p(false);
            } else {
                if (iOrdinal != 5) {
                    throw com.google.android.gms.measurement.internal.Z.j(1724927623, c0814p, false);
                }
                c0814p.X(1724953688);
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                pair = new Pair(com.quizlet.ui.resources.icons.d.t(c0814p), new C0861v(((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).Q0));
                c0814p.p(false);
            }
            androidx.compose.ui.graphics.painter.b bVar = (androidx.compose.ui.graphics.painter.b) pair.a;
            long j = ((C0861v) pair.b).a;
            if (bVar != null) {
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                c0814p.X(-147138910);
                com.quizlet.themes.m.g.h();
                com.quizlet.ui.resources.designsystem.generated.h hVar = com.quizlet.ui.resources.designsystem.generated.h.d;
                c0814p.p(false);
                androidx.compose.material3.D1.a(bVar, null, androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.g), j, c0814p, 48, 0);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(jVar, i, 14);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0065  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00f3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final kotlinx.serialization.KSerializer h(androidx.camera.camera2.internal.p0 r5, kotlin.reflect.o r6, boolean r7) {
        /*
            Method dump skipped, instructions count: 252
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.Q1.h(androidx.camera.camera2.internal.p0, kotlin.reflect.o, boolean):kotlinx.serialization.KSerializer");
    }
}
