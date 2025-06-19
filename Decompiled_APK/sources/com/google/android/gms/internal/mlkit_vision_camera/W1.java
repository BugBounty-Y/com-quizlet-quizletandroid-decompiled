package com.google.android.gms.internal.mlkit_vision_camera;

import android.content.Context;
import android.database.AbstractWindowedCursor;
import android.database.Cursor;
import android.database.MatrixCursor;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.AbstractC0809m0;
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
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.lifecycle.InterfaceC1261w;
import androidx.navigation.compose.C1280m;
import androidx.work.impl.WorkDatabase;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.A5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3137f0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.features.folders.composables.C4254j;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4392k;
import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Map;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.SerializationException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes2.dex */
public abstract class W1 implements Encoder, kotlinx.serialization.encoding.b {
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r13v21 */
    /* JADX WARN: Type inference failed for: r13v22 */
    /* JADX WARN: Type inference failed for: r13v23, types: [kotlinx.collections.immutable.g] */
    /* JADX WARN: Type inference failed for: r13v27, types: [java.lang.Object, kotlinx.collections.immutable.implementations.persistentOrderedMap.c] */
    /* JADX WARN: Type inference failed for: r13v28 */
    /* JADX WARN: Type inference failed for: r13v29 */
    /* JADX WARN: Type inference failed for: r13v37 */
    public static final void F(com.quizlet.features.practicetest.detail.data.F f, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        Object iVar;
        Object obj;
        final com.quizlet.assembly.compose.modals.x xVar;
        InterfaceC0773a0 interfaceC0773a0;
        boolean z;
        final com.quizlet.features.practicetest.detail.data.F f2;
        final com.quizlet.assembly.compose.modals.x xVar2;
        final Function1 function12;
        Function1 function13;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-334067398);
        int i2 = (c0814p.h(f) ? 4 : 2) | i | (c0814p.h(function1) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            f2 = f;
            function13 = function1;
        } else {
            Object obj2 = C0804k.a;
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(false, false, c0814p, 0, 7);
            Object[] objArr = new Object[0];
            c0814p.X(1948891049);
            Object objI = c0814p.I();
            if (objI == obj2) {
                objI = new C4392k(12);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            com.quizlet.assembly.compose.modals.x xVarH2 = Y5.h(false, false, c0814p, 0, 7);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            float fO = ((com.quizlet.themes.j) c0814p.j(com.quizlet.themes.l.a)).o();
            mVar.q();
            androidx.compose.ui.q qVarV = AbstractC0382e.v(qVarC, fO, com.quizlet.ui.resources.designsystem.generated.j.i);
            c0814p.X(-169662578);
            int i3 = androidx.compose.material3.I.a;
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            androidx.compose.foundation.layout.S0 s0E = C0380d.e(c0814p);
            int i4 = AbstractC0382e.g;
            C0374a c0374a = new C0374a(new C0416v0(s0E.g, i4 | 32), new C0416v0(C0380d.e(c0814p).k, i4));
            c0814p.p(false);
            androidx.compose.ui.q qVarB = androidx.compose.foundation.layout.U0.b(qVarV, c0374a);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.e, false);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarB);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p, R.string.practice_test_take_test_button);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.practice_test_configure_button);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarW = com.quizlet.ui.resources.icons.d.w(c0814p);
            c0814p.X(1773402709);
            boolean zF = c0814p.f(interfaceC0773a02) | c0814p.h(xVarH) | c0814p.h(f);
            int i6 = i2 & ContentType.LONG_FORM_ON_DEMAND;
            boolean zH = (i6 == 32) | zF | c0814p.h(xVarH2);
            Object objI2 = c0814p.I();
            if (zH || objI2 == obj2) {
                obj = obj2;
                xVar = xVarH2;
                interfaceC0773a0 = interfaceC0773a02;
                z = false;
                iVar = new com.braze.communication.i(xVarH, f, function1, xVar, interfaceC0773a0, 2);
                f2 = f;
                xVar2 = xVarH;
                function12 = function1;
                c0814p.i0(iVar);
            } else {
                f2 = f;
                xVar2 = xVarH;
                obj = obj2;
                function12 = function1;
                iVar = objI2;
                xVar = xVarH2;
                interfaceC0773a0 = interfaceC0773a02;
                z = false;
            }
            Function0 function0 = (Function0) iVar;
            c0814p.p(z);
            c0814p.X(1773396853);
            boolean zH2 = c0814p.h(xVar2) | (i6 == 32 ? true : z);
            Object objI3 = c0814p.I();
            if (zH2 || objI3 == obj) {
                objI3 = new com.quizlet.features.folders.addtofolder.composables.j(xVar2, function12, 4);
                c0814p.i0(objI3);
            }
            c0814p.p(z);
            Object obj3 = obj;
            T1.a(strD, strD2, function0, (Function0) objI3, null, 0, bVarW, false, c0814p, 0, 176);
            int i7 = f2.j.a;
            Map m = f2.i;
            Intrinsics.checkNotNullParameter(m, "<this>");
            ?? Build = m instanceof kotlinx.collections.immutable.g ? (kotlinx.collections.immutable.g) m : 0;
            if (Build == 0) {
                kotlinx.collections.immutable.f fVar = m instanceof kotlinx.collections.immutable.f ? (kotlinx.collections.immutable.f) m : null;
                kotlinx.collections.immutable.g gVarBuild = fVar != null ? fVar.build() : null;
                if (gVarBuild != null) {
                    Build = gVarBuild;
                } else {
                    Build = kotlinx.collections.immutable.implementations.persistentOrderedMap.c.e;
                    Intrinsics.e(Build, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.persistentOrderedMap.PersistentOrderedMap<K of kotlinx.collections.immutable.implementations.persistentOrderedMap.PersistentOrderedMap.Companion.emptyOf, V of kotlinx.collections.immutable.implementations.persistentOrderedMap.PersistentOrderedMap.Companion.emptyOf>");
                    Intrinsics.checkNotNullParameter(m, "m");
                    if (!m.isEmpty()) {
                        kotlinx.collections.immutable.implementations.persistentOrderedMap.d dVar = new kotlinx.collections.immutable.implementations.persistentOrderedMap.d(Build);
                        dVar.putAll(m);
                        Build = dVar.build();
                    }
                }
            }
            PracticeTestConfigurationData practiceTestConfigurationData = f2.j;
            boolean z2 = practiceTestConfigurationData.c;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "practice_test_configuration_test_tag");
            c0814p.X(1773435334);
            boolean zH3 = (i6 == 32) | c0814p.h(f2) | c0814p.h(xVar) | c0814p.h(xVar2);
            Object objI4 = c0814p.I();
            if (zH3 || objI4 == obj3) {
                objI4 = new kotlin.jvm.functions.c() { // from class: com.quizlet.features.practicetest.detail.e
                    @Override // kotlin.jvm.functions.c
                    public final Object invoke(Object obj4, Object obj5, Object obj6) {
                        int iIntValue = ((Integer) obj4).intValue();
                        boolean zBooleanValue = ((Boolean) obj5).booleanValue();
                        boolean zBooleanValue2 = ((Boolean) obj6).booleanValue();
                        if (f2.k) {
                            function12.invoke(new com.quizlet.features.practicetest.detail.data.m(iIntValue, zBooleanValue, zBooleanValue2));
                        } else {
                            x.d(xVar);
                        }
                        xVar2.a();
                        return Unit.a;
                    }
                };
                c0814p.i0(objI4);
            }
            kotlin.jvm.functions.c cVar = (kotlin.jvm.functions.c) objI4;
            com.quizlet.assembly.compose.modals.x xVar3 = xVar2;
            boolean zR = AbstractC4178x.r(c0814p, false, 1773453354, interfaceC0773a0) | (i6 == 32);
            Object objI5 = c0814p.I();
            if (zR || objI5 == obj3) {
                objI5 = new C4254j(2, function12, interfaceC0773a0);
                c0814p.i0(objI5);
            }
            c0814p.p(false);
            N1.a(xVar3, i7, Build, false, qVarG, practiceTestConfigurationData.b, z2, null, null, null, false, cVar, null, (kotlin.jvm.functions.d) objI5, c0814p, 27656, 0, 6016);
            c0814p = c0814p;
            c0814p.X(1773474369);
            boolean z3 = i6 == 32;
            Object objI6 = c0814p.I();
            if (z3 || objI6 == obj3) {
                objI6 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.m(28, function12);
                c0814p.i0(objI6);
            }
            Function0 function02 = (Function0) objI6;
            c0814p.p(false);
            c0814p.X(1773471648);
            boolean z4 = i6 == 32;
            Object objI7 = c0814p.I();
            if (z4 || objI7 == obj3) {
                objI7 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.m(29, function12);
                c0814p.i0(objI7);
            }
            c0814p.p(false);
            function13 = function1;
            S1.a(xVar, null, function02, (Function0) objI7, c0814p, 8);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(f2, function13, i, 26);
        }
    }

    public static final void G(com.quizlet.features.practicetest.detail.data.F f, Function0 function0, Function1 function1, androidx.compose.ui.q qVar, int i, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        int i4;
        int i5;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1115759443);
        int i6 = i2 | (c0814p.h(f) ? 4 : 2) | (c0814p.h(function0) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | (c0814p.f(qVar) ? 2048 : 1024) | 8192;
        if ((i6 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            i5 = i;
        } else {
            c0814p.S();
            if ((i2 & 1) == 0 || c0814p.w()) {
                i3 = i6 & (-57345);
                i4 = AbstractC3205m5.g(c0814p).a;
            } else {
                c0814p.Q();
                i3 = i6 & (-57345);
                i4 = i;
            }
            c0814p.q();
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            androidx.compose.ui.q qVarG = qVar.g(androidx.compose.foundation.layout.K0.c);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, gVar, c0814p, 48);
            int i7 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p, i7, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            androidx.compose.ui.q qVarQ = androidx.compose.foundation.layout.K0.q(AbstractC0382e.w(nVar, ((com.quizlet.themes.j) c0814p.j(com.quizlet.themes.l.a)).o(), DefinitionKt.NO_Float_VALUE, 2), DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.U0, 1);
            c0814p.X(-104156252);
            boolean zH = ((i3 & 896) == 256) | ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | c0814p.h(f) | c0814p.d(i4);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new androidx.navigation.serialization.k(f, function0, function1, i4);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3137f0.a(qVarQ, null, null, null, null, null, false, (Function1) objI, c0814p, 0, 254);
            c0814p.p(true);
            i5 = i4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i(f, function0, function1, qVar, i5, i2);
        }
    }

    public static final void H(int i, Function1 function1, InterfaceC0806l interfaceC0806l, int i2) {
        String strH;
        int i3 = 0;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2010936710);
        int i4 = (c0814p.d(i) ? 4 : 2) | i2 | (c0814p.h(function1) ? 32 : 16);
        if ((i4 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            c0814p.X(-1506047170);
            if (i > 0) {
                c0814p.X(-992157823);
                strH = AbstractC3106b5.b(R.plurals.paywall_get_quizlet_plus_free_trial_button, i, new Object[]{Integer.valueOf(i)}, c0814p);
                c0814p.p(false);
            } else {
                strH = com.google.android.gms.measurement.internal.Z.h(c0814p, -991988780, R.string.practice_test_paywall_container_button_text, c0814p, false);
            }
            String str = strH;
            c0814p.p(false);
            c0814p.X(2037415931);
            boolean z = (i4 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            if (z || objI == v) {
                objI = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.m(27, function1);
                c0814p.i0(objI);
            }
            Function0 function0 = (Function0) objI;
            c0814p.p(false);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            c0814p.X(-169662578);
            int i5 = androidx.compose.material3.I.a;
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            androidx.compose.foundation.layout.S0 s0E = C0380d.e(c0814p);
            int i6 = AbstractC0382e.g;
            C0374a c0374a = new C0374a(new C0416v0(s0E.g, 32 | i6), new C0416v0(C0380d.e(c0814p).k, i6));
            c0814p.p(false);
            P1.a(0, 0, c0814p, androidx.compose.foundation.layout.U0.b(nVar, c0374a), str, function0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.detail.d(i, i2, i3, function1);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r15v0 */
    /* JADX WARN: Type inference failed for: r15v7 */
    public static final void I(Function1 navigateToProfile, Function0 closePracticeTestAction, Function1 navigateShare, kotlin.jvm.functions.d navigateToTakeTest, Function2 navigateToResults, Function1 navigateToWebPage, Function1 navigateToLogin, Function1 navigateToSignUp, Function2 function2, com.quizlet.features.practicetest.detail.viewmodel.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        int i3;
        com.quizlet.features.practicetest.detail.viewmodel.a aVar2;
        androidx.compose.runtime.H0 h0;
        Object iVar;
        com.quizlet.features.practicetest.detail.viewmodel.a aVar3;
        kotlinx.coroutines.flow.d0 d0Var;
        androidx.compose.runtime.V v;
        com.quizlet.assembly.compose.modals.x xVar;
        C0814p c0814p;
        androidx.compose.runtime.V v2;
        C0814p c0814p2;
        com.quizlet.features.practicetest.detail.viewmodel.a aVar4;
        com.quizlet.features.practicetest.detail.viewmodel.a aVar5;
        Intrinsics.checkNotNullParameter(navigateToProfile, "navigateToProfile");
        Intrinsics.checkNotNullParameter(closePracticeTestAction, "closePracticeTestAction");
        Intrinsics.checkNotNullParameter(navigateShare, "navigateShare");
        Intrinsics.checkNotNullParameter(navigateToTakeTest, "navigateToTakeTest");
        Intrinsics.checkNotNullParameter(navigateToResults, "navigateToResults");
        Intrinsics.checkNotNullParameter(navigateToWebPage, "navigateToWebPage");
        Intrinsics.checkNotNullParameter(navigateToLogin, "navigateToLogin");
        Intrinsics.checkNotNullParameter(navigateToSignUp, "navigateToSignUp");
        C0814p c0814p3 = (C0814p) interfaceC0806l;
        c0814p3.Z(386370750);
        int i4 = i | (c0814p3.h(navigateToProfile) ? 4 : 2) | (c0814p3.h(navigateShare) ? 256 : 128) | (c0814p3.h(navigateToTakeTest) ? 2048 : 1024) | (c0814p3.h(navigateToResults) ? 16384 : 8192) | (c0814p3.h(navigateToWebPage) ? 131072 : 65536) | (c0814p3.h(navigateToLogin) ? 1048576 : 524288) | (c0814p3.h(navigateToSignUp) ? 8388608 : 4194304) | (c0814p3.h(function2) ? 67108864 : 33554432) | 268435456;
        if ((i4 & 306783379) == 306783378 && c0814p3.x()) {
            c0814p3.Q();
            aVar5 = aVar;
        } else {
            c0814p3.S();
            if ((i & 1) == 0 || c0814p3.w()) {
                c0814p3.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p3);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p3);
                c0814p3.Y(1729797275);
                i2 = 0;
                Object objE = AbstractC3417z1.e(com.quizlet.features.practicetest.detail.viewmodel.i.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p3);
                c0814p3 = c0814p3;
                c0814p3.p(false);
                c0814p3.p(false);
                com.quizlet.features.practicetest.detail.viewmodel.a aVar6 = (com.quizlet.features.practicetest.detail.viewmodel.a) objE;
                i3 = i4 & (-1879048193);
                aVar2 = aVar6;
            } else {
                c0814p3.Q();
                i3 = i4 & (-1879048193);
                i2 = 0;
                aVar2 = aVar;
            }
            c0814p3.q();
            com.quizlet.features.practicetest.detail.viewmodel.i iVar2 = (com.quizlet.features.practicetest.detail.viewmodel.i) aVar2;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(iVar2.l, c0814p3);
            Context context = (Context) c0814p3.j(AndroidCompositionLocals_androidKt.b);
            androidx.work.impl.t.a(i2, closePracticeTestAction, c0814p3, 48, 1);
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(true, i2, c0814p3, 6, 6);
            int i5 = i3;
            Object[] objArr = new Object[i2];
            c0814p3.X(-371336933);
            Object objI = c0814p3.I();
            androidx.compose.runtime.V v3 = C0804k.a;
            if (objI == v3) {
                objI = new C4392k(13);
                c0814p3.i0(objI);
            }
            c0814p3.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p3, 3072, 6);
            Object[] objArr2 = new Object[0];
            c0814p3.X(-371334285);
            Object objI2 = c0814p3.I();
            if (objI2 == v3) {
                objI2 = new C4392k(14);
                c0814p3.i0(objI2);
            }
            c0814p3.p(false);
            com.quizlet.features.practicetest.detail.viewmodel.a aVar7 = aVar2;
            androidx.compose.runtime.H0 h02 = (androidx.compose.runtime.H0) L4.d(objArr2, null, (Function0) objI2, c0814p3, 3072, 6);
            Object[] objArr3 = new Object[0];
            c0814p3.X(-371329765);
            Object objI3 = c0814p3.I();
            if (objI3 == v3) {
                objI3 = new C4392k(15);
                c0814p3.i0(objI3);
            }
            c0814p3.p(false);
            C0814p c0814p4 = c0814p3;
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) L4.d(objArr3, null, (Function0) objI3, c0814p3, 3072, 6);
            kotlinx.coroutines.flow.d0 d0Var2 = iVar2.k;
            c0814p4.X(-371325315);
            boolean zH = ((i5 & 896) == 256) | ((i5 & 14) == 4) | ((i5 & 7168) == 2048) | ((57344 & i5) == 16384) | ((458752 & i5) == 131072) | ((3670016 & i5) == 1048576) | c0814p4.h(context) | ((29360128 & i5) == 8388608) | ((i5 & 234881024) == 67108864) | c0814p4.f(h02) | c0814p4.f(interfaceC0773a0) | c0814p4.f(interfaceC0773a02) | c0814p4.h(xVarH);
            Object objI4 = c0814p4.I();
            if (zH || objI4 == v3) {
                h0 = h02;
                aVar3 = aVar7;
                d0Var = d0Var2;
                v = v3;
                iVar = new com.quizlet.features.practicetest.detail.i(navigateToProfile, closePracticeTestAction, navigateShare, navigateToTakeTest, navigateToResults, navigateToWebPage, navigateToLogin, context, navigateToSignUp, function2, xVarH, h0, interfaceC0773a0, interfaceC0773a02, null);
                xVar = xVarH;
                c0814p = c0814p4;
                c0814p.i0(iVar);
            } else {
                aVar3 = aVar7;
                h0 = h02;
                d0Var = d0Var2;
                xVar = xVarH;
                iVar = objI4;
                v = v3;
                c0814p = c0814p4;
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            AbstractC0809m0 abstractC0809m0 = androidx.lifecycle.compose.g.a;
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) iVar, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            kotlinx.coroutines.flow.d0 d0Var3 = d0Var;
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var3) | c0814p.f(interfaceC0773a0D);
            Object objI5 = c0814p.I();
            androidx.compose.runtime.V v4 = v;
            if (zF || objI5 == v4) {
                objI5 = new com.quizlet.features.practicetest.detail.h(interfaceC0773a0D, j, null, d0Var3);
                c0814p.i0(objI5);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI5);
            c0814p.p(false);
            androidx.lifecycle.J j2 = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            c0814p.X(-371251006);
            com.quizlet.features.practicetest.detail.viewmodel.a aVar8 = aVar3;
            boolean zH2 = c0814p.h(j2) | c0814p.h(aVar8);
            Object objI6 = c0814p.I();
            if (zH2 || objI6 == v4) {
                objI6 = new com.quizlet.features.practicetest.detail.l(j2, aVar8, null);
                c0814p.i0(objI6);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI6);
            com.quizlet.features.practicetest.detail.data.I i6 = (com.quizlet.features.practicetest.detail.data.I) interfaceC0773a0G.getValue();
            c0814p.X(-371243148);
            boolean zH3 = c0814p.h(aVar8);
            Object objI7 = c0814p.I();
            if (zH3 || objI7 == v4) {
                com.quizlet.features.notes.detail.composables.magicnotesdetail.G g = new com.quizlet.features.notes.detail.composables.magicnotesdetail.G(1, aVar8, com.quizlet.features.practicetest.detail.viewmodel.a.class, "onEvent", "onEvent(Lcom/quizlet/features/practicetest/detail/data/PracticeTestDetailEvent;)V", 0, 11);
                c0814p.i0(g);
                objI7 = g;
            }
            c0814p.p(false);
            J(i6, (Function1) ((kotlin.reflect.f) objI7), c0814p, 0, 0);
            c0814p.X(-371241887);
            if (((Boolean) interfaceC0773a0.getValue()).booleanValue()) {
                int i7 = h0.i();
                c0814p.X(-371236323);
                boolean zF2 = c0814p.f(interfaceC0773a0);
                Object objI8 = c0814p.I();
                if (zF2 || objI8 == v4) {
                    objI8 = new androidx.navigation.compose.z(interfaceC0773a0, 27);
                    c0814p.i0(objI8);
                }
                Function0 function0 = (Function0) objI8;
                boolean zR = AbstractC4178x.r(c0814p, false, -371234371, interfaceC0773a0);
                Object objI9 = c0814p.I();
                if (zR || objI9 == v4) {
                    objI9 = new androidx.navigation.compose.z(interfaceC0773a0, 28);
                    c0814p.i0(objI9);
                }
                c0814p.p(false);
                C0814p c0814p5 = c0814p;
                v2 = v4;
                c0814p2 = c0814p5;
                aVar4 = aVar8;
                W5.a(R.string.OK, i7, null, function0, (Function0) objI9, null, null, null, c0814p2, 0, 228);
            } else {
                C0814p c0814p6 = c0814p;
                v2 = v4;
                c0814p2 = c0814p6;
                aVar4 = aVar8;
            }
            c0814p2.p(false);
            com.quizlet.features.practicetest.detail.data.I i8 = (com.quizlet.features.practicetest.detail.data.I) interfaceC0773a0G.getValue();
            c0814p2.X(-371231833);
            if (i8 instanceof com.quizlet.features.practicetest.detail.data.F) {
                Object[] objArr4 = {Boolean.valueOf(((com.quizlet.features.practicetest.detail.data.F) i8).m)};
                c0814p2.X(-371227742);
                boolean zH4 = c0814p2.h(i8);
                Object objI10 = c0814p2.I();
                if (zH4 || objI10 == v2) {
                    objI10 = new com.quizlet.featuregate.growthbook.a((com.quizlet.features.practicetest.detail.data.F) i8, 8);
                    c0814p2.i0(objI10);
                }
                c0814p2.p(false);
                InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) L4.d(objArr4, null, (Function0) objI10, c0814p2, 0, 6);
                boolean zBooleanValue = ((Boolean) interfaceC0773a03.getValue()).booleanValue();
                String strD = AbstractC3106b5.d(c0814p2, R.string.practice_test_privacy_settings_public_label_description);
                String strD2 = AbstractC3106b5.d(c0814p2, R.string.practice_test_privacy_settings_private_label_description);
                c0814p2.X(-371209348);
                boolean zF3 = c0814p2.f(interfaceC0773a03) | c0814p2.h(aVar4);
                Object objI11 = c0814p2.I();
                if (zF3 || objI11 == v2) {
                    objI11 = new androidx.lifecycle.u0(26, aVar4, interfaceC0773a03);
                    c0814p2.i0(objI11);
                }
                c0814p2.p(false);
                A5.b(zBooleanValue, xVar, strD, strD2, (Function1) objI11, c0814p2, 64);
            }
            c0814p2.p(false);
            if (((Boolean) interfaceC0773a02.getValue()).booleanValue()) {
                c0814p2.X(-371188156);
                boolean zH5 = c0814p2.h(aVar4);
                Object objI12 = c0814p2.I();
                if (zH5 || objI12 == v2) {
                    objI12 = new com.quizlet.featuregate.growthbook.a(aVar4, 9);
                    c0814p2.i0(objI12);
                }
                Function0 function02 = (Function0) objI12;
                boolean zR2 = AbstractC4178x.r(c0814p2, false, -371184987, interfaceC0773a02);
                Object objI13 = c0814p2.I();
                if (zR2 || objI13 == v2) {
                    objI13 = new androidx.navigation.compose.z(interfaceC0773a02, 29);
                    c0814p2.i0(objI13);
                }
                c0814p2.p(false);
                W5.a(R.string.practice_test_privacy_settings_dialog_confirm_button, R.string.practice_test_privacy_settings_dialog_subheader, null, function02, (Function0) objI13, null, Integer.valueOf(R.string.practice_test_privacy_settings_dialog_header), Integer.valueOf(R.string.practice_test_privacy_settings_dialog_close_button), c0814p2, 0, 36);
            }
            c0814p3 = c0814p2;
            aVar5 = aVar4;
        }
        C0813o0 c0813o0R = c0814p3.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.detail.c(navigateToProfile, closePracticeTestAction, navigateShare, navigateToTakeTest, navigateToResults, navigateToWebPage, navigateToLogin, navigateToSignUp, function2, aVar5, i);
        }
    }

    public static final void J(com.quizlet.features.practicetest.detail.data.I i, Function1 function1, InterfaceC0806l interfaceC0806l, int i2, int i3) {
        Function1 function12;
        int i4;
        Function1 function13;
        Function1 function14;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1007284468);
        int i5 = i2 | (c0814p.f(i) ? 4 : 2);
        int i6 = i3 & 2;
        if (i6 != 0) {
            i4 = i5 | 48;
            function12 = function1;
        } else {
            function12 = function1;
            i4 = i5 | (c0814p.h(function12) ? 32 : 16);
        }
        if ((i4 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function14 = function12;
        } else {
            if (i6 != 0) {
                c0814p.X(-1832833978);
                Object objI = c0814p.I();
                if (objI == C0804k.a) {
                    objI = new C4237k(27);
                    c0814p.i0(objI);
                }
                function13 = (Function1) objI;
                c0814p.p(false);
            } else {
                function13 = function12;
            }
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(true, false, c0814p, 6, 6);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "practice_test_detail_screen");
            long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
            c0814p.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            AbstractC0725t3.a(qVarG, androidx.compose.runtime.internal.e.e(993281464, new com.quizlet.assembly.compose.menu.l(i, function13, xVarH, 17), c0814p), androidx.compose.runtime.internal.e.e(1941771193, new androidx.navigation.compose.o(28, i, function13), c0814p), null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(1069491331, new com.quizlet.features.practicetest.detail.n(i, function13, xVarH), c0814p), c0814p, 805306806, 184);
            function14 = function13;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(i, function14, i2, i3, 13);
        }
    }

    public static final void K(int i, int i2, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String str) {
        androidx.compose.ui.q qVar2;
        int i3;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1902933118);
        int i4 = i | (c0814p2.f(str) ? 4 : 2);
        int i5 = i2 & 2;
        if (i5 != 0) {
            i3 = i4 | 48;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = i4 | (c0814p2.f(qVar2) ? 32 : 16);
        }
        if ((i3 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.q qVar3 = i5 != 0 ? androidx.compose.ui.n.b : qVar2;
            c0814p = c0814p2;
            Q4.b(str, androidx.compose.foundation.layout.K0.c(qVar3, 1.0f), 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).i, c0814p, i3 & 14, 0, 65532);
            qVar2 = qVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.m(str, qVar2, i, i2, 3);
        }
    }

    public static final Cursor N(WorkDatabase db, androidx.sqlite.db.g sqLiteQuery, boolean z) {
        Intrinsics.checkNotNullParameter(db, "db");
        Intrinsics.checkNotNullParameter(sqLiteQuery, "sqLiteQuery");
        Cursor c = db.m(sqLiteQuery);
        if (z && (c instanceof AbstractWindowedCursor)) {
            AbstractWindowedCursor abstractWindowedCursor = (AbstractWindowedCursor) c;
            int count = abstractWindowedCursor.getCount();
            if ((abstractWindowedCursor.hasWindow() ? abstractWindowedCursor.getWindow().getNumRows() : count) < count) {
                Intrinsics.checkNotNullParameter(c, "c");
                try {
                    MatrixCursor matrixCursor = new MatrixCursor(c.getColumnNames(), c.getCount());
                    while (c.moveToNext()) {
                        Object[] objArr = new Object[c.getColumnCount()];
                        int columnCount = c.getColumnCount();
                        for (int i = 0; i < columnCount; i++) {
                            int type = c.getType(i);
                            if (type == 0) {
                                objArr[i] = null;
                            } else if (type == 1) {
                                objArr[i] = Long.valueOf(c.getLong(i));
                            } else if (type == 2) {
                                objArr[i] = Double.valueOf(c.getDouble(i));
                            } else if (type == 3) {
                                objArr[i] = c.getString(i);
                            } else {
                                if (type != 4) {
                                    throw new IllegalStateException();
                                }
                                objArr[i] = c.getBlob(i);
                            }
                        }
                        matrixCursor.addRow(objArr);
                    }
                    AbstractC3336f.c(c, null);
                    return matrixCursor;
                } finally {
                }
            }
        }
        return c;
    }

    @Override // kotlinx.serialization.encoding.b
    public void A(SerialDescriptor descriptor, int i, double d) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        L(descriptor, i);
        e(d);
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public void B(long j) {
        M(Long.valueOf(j));
    }

    @Override // kotlinx.serialization.encoding.b
    public void C(SerialDescriptor descriptor, int i, long j) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        L(descriptor, i);
        B(j);
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public void E(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        M(value);
    }

    public void L(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
    }

    public void M(Object value) {
        Intrinsics.checkNotNullParameter(value, "value");
        throw new SerializationException("Non-serializable " + kotlin.jvm.internal.K.a(value.getClass()) + " is not supported by " + kotlin.jvm.internal.K.a(getClass()) + " encoder");
    }

    @Override // kotlinx.serialization.encoding.b
    public void b(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public kotlinx.serialization.encoding.b c(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return this;
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public void d() {
        throw new SerializationException("'null' is not supported by default");
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public void e(double d) {
        M(Double.valueOf(d));
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public void f(short s) {
        M(Short.valueOf(s));
    }

    @Override // kotlinx.serialization.encoding.b
    public void g(kotlinx.serialization.internal.f0 descriptor, int i, short s) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        L(descriptor, i);
        f(s);
    }

    @Override // kotlinx.serialization.encoding.b
    public void h(kotlinx.serialization.internal.f0 descriptor, int i, char c) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        L(descriptor, i);
        n(c);
    }

    @Override // kotlinx.serialization.encoding.b
    public void i(SerialDescriptor descriptor, int i, KSerializer serializer, Object obj) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        L(descriptor, i);
        y(serializer, obj);
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public void j(byte b) {
        M(Byte.valueOf(b));
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public void k(boolean z) {
        M(Boolean.valueOf(z));
    }

    @Override // kotlinx.serialization.encoding.b
    public void l(int i, int i2, SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        L(descriptor, i);
        w(i2);
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public void m(float f) {
        M(Float.valueOf(f));
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public void n(char c) {
        M(Character.valueOf(c));
    }

    @Override // kotlinx.serialization.encoding.b
    public void o(kotlinx.serialization.internal.f0 descriptor, int i, byte b) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        L(descriptor, i);
        j(b);
    }

    @Override // kotlinx.serialization.encoding.b
    public void p(SerialDescriptor descriptor, int i, boolean z) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        L(descriptor, i);
        k(z);
    }

    @Override // kotlinx.serialization.encoding.b
    public void r(SerialDescriptor descriptor, int i, String value) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(value, "value");
        L(descriptor, i);
        E(value);
    }

    @Override // kotlinx.serialization.encoding.b
    public void s(SerialDescriptor descriptor, int i, KSerializer serializer, Object obj) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        L(descriptor, i);
        q(serializer, obj);
    }

    @Override // kotlinx.serialization.encoding.b
    public void t(kotlinx.serialization.internal.f0 descriptor, int i, float f) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        L(descriptor, i);
        m(f);
    }

    @Override // kotlinx.serialization.encoding.b
    public Encoder u(kotlinx.serialization.internal.f0 descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        L(descriptor, i);
        return x(descriptor.i(i));
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public void v(SerialDescriptor enumDescriptor, int i) {
        Intrinsics.checkNotNullParameter(enumDescriptor, "enumDescriptor");
        M(Integer.valueOf(i));
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public void w(int i) {
        M(Integer.valueOf(i));
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public Encoder x(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return this;
    }
}
