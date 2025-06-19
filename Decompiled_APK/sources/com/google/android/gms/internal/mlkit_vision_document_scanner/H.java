package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.mayakapps.kache.C4038g;
import com.mayakapps.kache.C4039h;
import com.mayakapps.kache.C4040i;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class H {
    /* JADX WARN: Type inference failed for: r8v0, types: [kotlin.jvm.functions.Function2, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r9v0, types: [kotlin.jvm.functions.d, kotlin.jvm.internal.r] */
    public static final com.mayakapps.kache.u a(long j, Function1 configuration) {
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        if (j <= 0) {
            throw new IllegalArgumentException("maxSize must be positive value");
        }
        C4040i c4040i = new C4040i();
        c4040i.a = com.mayakapps.kache.x.a;
        c4040i.b = kotlinx.coroutines.E.c(kotlinx.coroutines.O.a);
        c4040i.c = C4039h.a;
        c4040i.d = C4038g.a;
        kotlin.time.h hVar = kotlin.time.h.a;
        kotlin.time.b.b.getClass();
        long j2 = kotlin.time.b.c;
        configuration.invoke(c4040i);
        return new com.mayakapps.kache.u(j, c4040i.a, c4040i.b, c4040i.c, c4040i.d, hVar, j2, j2);
    }

    public static final void b(String email, Function1 onNavigateToEmailSent, Function0 onDismiss, androidx.compose.ui.q qVar, com.quizlet.login.magiclink.viewmodel.b bVar, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.login.magiclink.viewmodel.b bVar2;
        int i2;
        androidx.compose.ui.q qVar2;
        androidx.compose.ui.q qVar3;
        com.quizlet.login.magiclink.viewmodel.b bVar3;
        Intrinsics.checkNotNullParameter(email, "email");
        Intrinsics.checkNotNullParameter(onNavigateToEmailSent, "onNavigateToEmailSent");
        Intrinsics.checkNotNullParameter(onDismiss, "onDismiss");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-124146226);
        int i3 = i | (c0814p.f(email) ? 4 : 2) | (c0814p.h(onNavigateToEmailSent) ? 32 : 16) | (c0814p.h(onDismiss) ? 256 : 128) | 11264;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            qVar3 = qVar;
            bVar3 = bVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                Object objE = AbstractC3417z1.e(com.quizlet.login.magiclink.viewmodel.j.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                bVar2 = (com.quizlet.login.magiclink.viewmodel.b) objE;
                i2 = i3 & (-57345);
                qVar2 = nVar;
            } else {
                c0814p.Q();
                bVar2 = bVar;
                i2 = i3 & (-57345);
                qVar2 = qVar;
            }
            c0814p.q();
            kotlinx.coroutines.flow.d0 d0Var = ((com.quizlet.login.magiclink.viewmodel.j) bVar2).e;
            c0814p.X(1243211475);
            boolean z = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.login.common.ui.m(onNavigateToEmailSent, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v) {
                objI2 = new com.quizlet.login.common.ui.l(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI2);
            c0814p.p(false);
            com.quizlet.login.magiclink.viewmodel.b bVar4 = bVar2;
            androidx.compose.material3.Z1.a(onDismiss, androidx.compose.runtime.internal.e.e(617822742, new com.quizlet.features.practicetest.results.i(18, bVar2, email), c0814p), androidx.compose.ui.platform.N.G(qVar2, "multipleAccountsFoundDialog"), androidx.compose.runtime.internal.e.e(-198224488, new com.quizlet.explanations.questiondetail.ui.composables.m(23, onDismiss), c0814p), com.quizlet.login.common.ui.h.a, com.quizlet.login.common.ui.h.b, null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), 0L, 0L, 0L, DefinitionKt.NO_Float_VALUE, null, c0814p, ((i2 >> 6) & 14) | 1772592, 0, 16016);
            c0814p = c0814p;
            qVar3 = qVar2;
            bVar3 = bVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(email, onNavigateToEmailSent, onDismiss, qVar3, bVar3, i);
        }
    }
}
