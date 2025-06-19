package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.animation.core.C0253l0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.quizlet.assembly.compose.modals.C4105d;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4739h;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public abstract class F4 {
    public static String a;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r5v27, types: [androidx.compose.ui.q] */
    public static final void a(androidx.compose.ui.n nVar, com.quizlet.quizletandroid.ui.globalnav.viewmodel.e eVar, com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L l, C4739h c4739h, com.quizlet.features.infra.snackbar.viewmodel.c cVar, com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar, androidx.compose.material.navigation.i iVar, androidx.navigation.H h, androidx.compose.material3.O3 o3, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        kotlin.coroutines.h hVar;
        C4739h c4739h2;
        int i2;
        com.quizlet.features.infra.snackbar.viewmodel.c cVar2;
        androidx.compose.material.navigation.i iVar2;
        androidx.navigation.H h2;
        androidx.compose.material3.O3 o32;
        androidx.compose.material3.O3 o33;
        com.quizlet.features.infra.snackbar.viewmodel.c cVar3;
        androidx.compose.material.navigation.i iVar3;
        androidx.compose.ui.n nVar3;
        C4739h c4739h3;
        androidx.navigation.H h3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-170030102);
        int i3 = i | 6 | (c0814p.h(eVar) ? 32 : 16) | (c0814p.h(l) ? 256 : 128) | 9216 | (c0814p.h(aVar) ? 131072 : 65536) | 105381888;
        if ((38347923 & i3) == 38347922 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar;
            c4739h3 = c4739h;
            cVar3 = cVar;
            iVar3 = iVar;
            h3 = h;
            o33 = o3;
        } else {
            c0814p.S();
            int i4 = i & 1;
            Object obj = C0804k.a;
            if (i4 == 0 || c0814p.w()) {
                nVar2 = androidx.compose.ui.n.b;
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                hVar = null;
                androidx.lifecycle.w0 w0VarE = AbstractC3417z1.e(C4739h.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                c4739h2 = (C4739h) w0VarE;
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A2 = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A2 == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC2 = AbstractC3405w1.c(c0A2, c0814p);
                c0814p.Y(1729797275);
                androidx.lifecycle.w0 w0VarE2 = AbstractC3417z1.e(com.quizlet.features.infra.snackbar.viewmodel.c.class, c0A2, null, fVarC2, c0A2 instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A2).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p = c0814p;
                c0814p.p(false);
                c0814p.p(false);
                com.quizlet.features.infra.snackbar.viewmodel.c cVar4 = (com.quizlet.features.infra.snackbar.viewmodel.c) w0VarE2;
                C0253l0 c0253l0 = new C0253l0(null, 7);
                androidx.compose.material.f0 f0Var = androidx.compose.material.f0.a;
                androidx.compose.material.e0 e0VarC = androidx.compose.material.Z.c(c0253l0, c0814p, 6, 12);
                boolean zF = c0814p.f(e0VarC);
                Object objI = c0814p.I();
                if (zF || objI == obj) {
                    objI = new androidx.compose.material.navigation.i(e0VarC);
                    c0814p.i0(objI);
                }
                androidx.compose.material.navigation.i iVar4 = (androidx.compose.material.navigation.i) objI;
                androidx.navigation.H hD = com.google.android.gms.internal.mlkit_vision_camera.O1.d(new androidx.navigation.W[]{iVar4}, c0814p);
                int i5 = i3 & (-33094657);
                c0814p.X(961584737);
                Object objI2 = c0814p.I();
                if (objI2 == obj) {
                    objI2 = new androidx.compose.material3.O3();
                    c0814p.i0(objI2);
                }
                c0814p.p(false);
                i2 = i5;
                cVar2 = cVar4;
                iVar2 = iVar4;
                h2 = hD;
                o32 = (androidx.compose.material3.O3) objI2;
            } else {
                c0814p.Q();
                int i6 = i3 & (-33094657);
                nVar2 = nVar;
                c4739h2 = c4739h;
                cVar2 = cVar;
                iVar2 = iVar;
                h2 = h;
                o32 = o3;
                i2 = i6;
                hVar = null;
            }
            c0814p.q();
            kotlinx.coroutines.flow.d0 d0Var = cVar2.b;
            c0814p.X(961587827);
            Object objI3 = c0814p.I();
            if (objI3 == obj) {
                objI3 = new com.quizlet.quizletandroid.ui.globalnav.composable.r(o32, hVar);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI3, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF2 = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI4 = c0814p.I();
            if (zF2 || objI4 == obj) {
                objI4 = new com.quizlet.quizletandroid.ui.globalnav.composable.q(interfaceC0773a0D, j, hVar, d0Var);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI4);
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(eVar.e, c0814p);
            InterfaceC0773a0 interfaceC0773a0G2 = AbstractC3409x1.g(eVar.i, c0814p);
            InterfaceC0773a0 interfaceC0773a0L = C0776c.l(new kotlinx.coroutines.flow.Y(h2.b.z), null, null, c0814p, 48, 2);
            C0814p c0814p2 = c0814p;
            long jG = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g();
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.f();
            float f = com.quizlet.ui.resources.designsystem.generated.f.i;
            mVar.f();
            androidx.compose.foundation.shape.d dVarB = androidx.compose.foundation.shape.e.b(f, f, 12);
            ?? r5 = hVar;
            androidx.navigation.H h4 = h2;
            C4739h c4739h4 = c4739h2;
            androidx.compose.material3.O3 o34 = o32;
            androidx.compose.ui.n nVar4 = nVar2;
            com.google.android.gms.internal.mlkit_vision_barcode.E0.a(iVar2, nVar4, false, dVarB, DefinitionKt.NO_Float_VALUE, jG, 0L, 0L, androidx.compose.runtime.internal.e.e(-440583036, new C4105d(eVar, h4, interfaceC0773a0G, interfaceC0773a0L, o34, c4739h4, interfaceC0773a0G2, 1), c0814p2), c0814p2, 100663352);
            com.quizlet.features.infra.compatibility.a aVar2 = (com.quizlet.features.infra.compatibility.a) AbstractC3409x1.g(eVar.g, c0814p2).getValue();
            c0814p2.X(961689453);
            if (aVar2 != null) {
                com.google.android.gms.internal.mlkit_vision_barcode.C5.a(aVar2, r5, c0814p2, 0);
            }
            c0814p2.p(false);
            c0814p2.X(961700291);
            boolean zH = c0814p2.h(eVar);
            Object objI5 = c0814p2.I();
            if (zH || objI5 == obj) {
                com.quizlet.login.common.navigation.d dVar = new com.quizlet.login.common.navigation.d(1, eVar, com.quizlet.quizletandroid.ui.globalnav.viewmodel.e.class, "onEvent", "onEvent(Lcom/quizlet/quizletandroid/ui/globalnav/data/GlobalNavigationEvent;)V", 0, 22);
                c0814p2.i0(dVar);
                objI5 = dVar;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            E4.a(h4, l, c4739h4, aVar, (Function1) ((kotlin.reflect.f) objI5), c0814p, ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | ((i2 >> 6) & 7168));
            o33 = o34;
            cVar3 = cVar2;
            iVar3 = iVar2;
            nVar3 = nVar4;
            c4739h3 = c4739h4;
            h3 = h4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.settings.ui.a(nVar3, eVar, l, c4739h3, cVar3, aVar, iVar3, h3, o33, i, 3);
        }
    }
}
