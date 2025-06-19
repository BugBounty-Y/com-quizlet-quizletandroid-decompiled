package org.jsoup.helper;

import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.material3.O3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.n;
import androidx.lifecycle.B;
import androidx.lifecycle.C0;
import androidx.lifecycle.InterfaceC1261w;
import androidx.lifecycle.J;
import androidx.lifecycle.compose.g;
import androidx.lifecycle.w0;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.quizlet.assembly.compose.buttons.A;
import com.quizlet.assembly.compose.buttons.C4079d;
import com.quizlet.assembly.compose.input.m;
import com.quizlet.data.model.D2;
import com.quizlet.data.model.x2;
import com.quizlet.data.model.y2;
import com.quizlet.data.model.z2;
import com.quizlet.explanations.questiondetail.ui.composables.j;
import com.quizlet.explanations.textbook.ui.composables.e;
import com.quizlet.explanations.textbook.viewmodel.c;
import com.quizlet.quizletandroid.ui.studymodes.testmode.start.p;
import dagger.hilt.android.internal.lifecycle.f;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes3.dex */
public abstract class b {
    /* JADX WARN: Removed duplicated region for block: B:35:0x00ca  */
    /* JADX WARN: Removed duplicated region for block: B:37:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(com.quizlet.data.model.D2 r8, androidx.appcompat.view.a r9, androidx.compose.runtime.InterfaceC0806l r10, int r11) {
        /*
            r4 = r10
            androidx.compose.runtime.p r4 = (androidx.compose.runtime.C0814p) r4
            r10 = 1472329298(0x57c1f652, float:4.2652736E14)
            r4.Z(r10)
            boolean r10 = r4.h(r8)
            if (r10 == 0) goto L11
            r10 = 4
            goto L12
        L11:
            r10 = 2
        L12:
            r10 = r10 | r11
            boolean r0 = r4.f(r9)
            if (r0 == 0) goto L1c
            r0 = 32
            goto L1e
        L1c:
            r0 = 16
        L1e:
            r10 = r10 | r0
            r0 = r10 & 19
            r1 = 18
            if (r0 != r1) goto L32
            boolean r0 = r4.x()
            if (r0 != 0) goto L2c
            goto L32
        L2c:
            r4.Q()
        L2f:
            r2 = r9
            goto Lc4
        L32:
            androidx.compose.runtime.X0 r0 = androidx.glance.j.a
            java.lang.Object r0 = r4.j(r0)
            androidx.compose.ui.unit.g r0 = (androidx.compose.ui.unit.g) r0
            long r0 = r0.a
            float r2 = androidx.compose.ui.unit.g.b(r0)
            r3 = 250(0xfa, float:3.5E-43)
            float r3 = (float) r3
            int r2 = java.lang.Float.compare(r2, r3)
            r3 = 0
            r5 = 200(0xc8, float:2.8E-43)
            r6 = 0
            if (r2 >= 0) goto L69
            float r2 = androidx.compose.ui.unit.g.a(r0)
            float r7 = (float) r5
            int r2 = java.lang.Float.compare(r2, r7)
            if (r2 >= 0) goto L69
            r0 = 1966172320(0x753168a0, float:2.2489223E32)
            r4.X(r0)
            com.quizlet.data.model.C2 r0 = r8.a
            r10 = r10 & 112(0x70, float:1.57E-43)
            com.quizlet.login.common.navigation.e.a(r0, r9, r3, r4, r10)
            r4.p(r6)
            goto L2f
        L69:
            java.util.ArrayList r2 = r8.b
            boolean r2 = r2.isEmpty()
            if (r2 == 0) goto L82
            r0 = 1966175246(0x7531740e, float:2.2494883E32)
            r4.X(r0)
            int r10 = r10 >> 3
            r10 = r10 & 14
            org.chromium.support_lib_boundary.util.a.a(r9, r3, r4, r10)
            r4.p(r6)
            goto L2f
        L82:
            float r0 = androidx.compose.ui.unit.g.a(r0)
            float r1 = (float) r5
            int r0 = java.lang.Float.compare(r0, r1)
            if (r0 >= 0) goto L8f
            r0 = 1
            goto L90
        L8f:
            r0 = r6
        L90:
            java.util.ArrayList r1 = r8.b
            r2 = r0
            com.quizlet.data.model.C2 r0 = r8.a
            if (r2 == 0) goto Lae
            r2 = 1966177854(0x75317e3e, float:2.2499928E32)
            r4.X(r2)
            kotlinx.collections.immutable.b r1 = com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1.i(r1)
            int r10 = r10 << 3
            r5 = r10 & 896(0x380, float:1.256E-42)
            r3 = 0
            r2 = r9
            okhttp3.internal.platform.m.a(r0, r1, r2, r3, r4, r5)
            r4.p(r6)
            goto Lc4
        Lae:
            r2 = r9
            r9 = 1966181274(0x75318b9a, float:2.2506543E32)
            r4.X(r9)
            kotlinx.collections.immutable.b r1 = com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1.i(r1)
            int r9 = r10 << 3
            r5 = r9 & 896(0x380, float:1.256E-42)
            r3 = 0
            _COROUTINE.a.d(r0, r1, r2, r3, r4, r5)
            r4.p(r6)
        Lc4:
            androidx.compose.runtime.o0 r9 = r4.r()
            if (r9 == 0) goto Ld2
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.p r10 = new com.quizlet.quizletandroid.ui.studymodes.testmode.start.p
            r0 = 2
            r10.<init>(r8, r2, r11, r0)
            r9.d = r10
        Ld2:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.jsoup.helper.b.a(com.quizlet.data.model.D2, androidx.appcompat.view.a, androidx.compose.runtime.l, int):void");
    }

    public static final void b(n nVar, c cVar, com.quizlet.features.infra.folder.menu.viewmodel.n nVar2, InterfaceC0773a0 interfaceC0773a0, Function1 function1, Function1 function12, O3 o3, InterfaceC0806l interfaceC0806l, int i) {
        c cVar2;
        O3 o32;
        n nVar3;
        com.quizlet.features.infra.folder.menu.viewmodel.n nVar4;
        com.quizlet.features.infra.folder.menu.viewmodel.n nVar5;
        c cVar3;
        n nVar6;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1936571445);
        if (((i | 150 | (c0814p.f(interfaceC0773a0) ? 2048 : 1024) | (c0814p.h(function1) ? 16384 : 8192) | (c0814p.h(function12) ? 131072 : 65536) | 1572864) & 599187) == 599186 && c0814p.x()) {
            c0814p.Q();
            nVar6 = nVar;
            cVar3 = cVar;
            nVar5 = nVar2;
            o32 = o3;
        } else {
            c0814p.S();
            int i2 = i & 1;
            V v = C0804k.a;
            if (i2 == 0 || c0814p.w()) {
                n nVar7 = n.b;
                c0814p.Y(1890788296);
                C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                w0 w0VarE = AbstractC3417z1.e(c.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                cVar2 = (c) w0VarE;
                c0814p.Y(1890788296);
                C0 c0A2 = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A2 == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                f fVarC2 = AbstractC3405w1.c(c0A2, c0814p);
                c0814p.Y(1729797275);
                Object objE = AbstractC3417z1.e(com.quizlet.features.infra.folder.menu.viewmodel.a.class, c0A2, null, fVarC2, c0A2 instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A2).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                com.quizlet.features.infra.folder.menu.viewmodel.n nVar8 = (com.quizlet.features.infra.folder.menu.viewmodel.n) objE;
                c0814p.X(-1754288149);
                Object objI = c0814p.I();
                if (objI == v) {
                    objI = new O3();
                    c0814p.i0(objI);
                }
                o32 = (O3) objI;
                c0814p.p(false);
                nVar3 = nVar7;
                nVar4 = nVar8;
            } else {
                c0814p.Q();
                nVar3 = nVar;
                cVar2 = cVar;
                nVar4 = nVar2;
                o32 = o3;
            }
            c0814p.q();
            InterfaceC4992i interfaceC4992iU = nVar4.u();
            c0814p.X(-1754284487);
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new com.quizlet.explanations.textbook.ui.composables.f(o32, null);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            J j = (J) c0814p.j(g.a);
            B b = B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(interfaceC4992iU) | c0814p.f(interfaceC0773a0D);
            Object objI3 = c0814p.I();
            if (zF || objI3 == v) {
                objI3 = new e(interfaceC0773a0D, j, null, interfaceC4992iU);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI3);
            c0814p.p(false);
            c cVar4 = cVar2;
            nVar5 = nVar4;
            AbstractC0725t3.a(nVar3, androidx.compose.runtime.internal.e.e(1881974919, new A(cVar2, interfaceC0773a0, nVar4, function12, 3), c0814p), null, androidx.compose.runtime.internal.e.e(1612809541, new j(o32, nVar5, 1), c0814p), null, 0, 0L, 0L, null, androidx.compose.runtime.internal.e.e(1668557276, new m(4, cVar4, function1), c0814p), c0814p, 805309494, com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR);
            c0814p = c0814p;
            cVar3 = cVar4;
            nVar6 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4079d(nVar6, cVar3, nVar5, interfaceC0773a0, function1, function12, o32, i, 1);
        }
    }

    public static final void c(x2 x2Var, androidx.appcompat.view.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1787194490);
        int i2 = (c0814p.h(x2Var) ? 4 : 2) | i | (c0814p.f(aVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else if (x2Var instanceof y2) {
            c0814p.X(-1018701924);
            kotlin.jvm.a.a(aVar, null, c0814p, (i2 >> 3) & 14);
            c0814p.p(false);
        } else if (x2Var instanceof z2) {
            c0814p.X(-1018699588);
            kotlin.jvm.a.a(aVar, null, c0814p, (i2 >> 3) & 14);
            c0814p.p(false);
        } else if (x2Var instanceof D2) {
            c0814p.X(-1018697107);
            a((D2) x2Var, aVar, c0814p, i2 & ContentType.LONG_FORM_ON_DEMAND);
            c0814p.p(false);
        } else {
            c0814p.X(-1018694692);
            kotlin.jvm.a.a(aVar, null, c0814p, (i2 >> 3) & 14);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new p(x2Var, aVar, i, 1);
        }
    }

    public static void d(boolean z) {
        if (!z) {
            throw new ValidationException("Must be true");
        }
    }

    public static void e(String str) {
        if (str == null || str.length() == 0) {
            throw new ValidationException("String must not be empty");
        }
    }

    public static void f(String str, String str2) {
        if (str == null || str.length() == 0) {
            throw new ValidationException(str2);
        }
    }

    public static void g(Object obj) {
        if (obj == null) {
            throw new ValidationException("Object must not be null");
        }
    }
}
