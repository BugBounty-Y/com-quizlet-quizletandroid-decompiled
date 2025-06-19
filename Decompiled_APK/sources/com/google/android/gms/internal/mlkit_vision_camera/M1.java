package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0811n0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.InterfaceC1261w;
import androidx.navigation.C1265a;
import androidx.navigation.C1291m;
import androidx.navigation.compose.C1268a;
import androidx.navigation.compose.C1280m;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.firebase.sessions.C4003z;
import com.quizlet.quizletandroid.R;
import java.util.concurrent.CancellationException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* loaded from: classes2.dex */
public abstract class M1 {
    public static final void a(C1291m c1291m, androidx.compose.runtime.saveable.f fVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(233973821);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(c1291m) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(fVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(dVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0776c.b(new C0811n0[]{androidx.lifecycle.viewmodel.compose.a.a.a(c1291m), androidx.lifecycle.compose.g.a.a(c1291m), androidx.savedstate.compose.a.a.a(c1291m)}, androidx.compose.runtime.internal.e.e(1808964477, new androidx.navigation.compose.o(1, fVar, dVar), c0814p), c0814p, 56);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 0, c1291m, fVar, dVar);
        }
    }

    public static final void b(androidx.compose.runtime.saveable.f fVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(832919318);
        int i2 = (c0814p.h(fVar) ? 4 : 2) | i | (c0814p.h(dVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new C1265a(11);
                c0814p.i0(objI);
            }
            Function1 function1 = (Function1) objI;
            androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
            if (c0A == null) {
                throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
            }
            C4950i c4950iA = kotlin.jvm.internal.K.a(C1268a.class);
            com.airbnb.lottie.network.d dVar2 = new com.airbnb.lottie.network.d(14);
            dVar2.c(kotlin.jvm.internal.K.a(C1268a.class), function1);
            C1268a c1268a = (C1268a) AbstractC3417z1.c(c0A, c4950iA, null, dVar2.e(), c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b);
            c1268a.c = new com.google.android.gms.auth.api.signin.internal.h(fVar);
            fVar.e(c1268a.b, dVar, c0814p, ((i2 << 6) & 896) | (i2 & ContentType.LONG_FORM_ON_DEMAND));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(fVar, dVar, i, 1);
        }
    }

    public static final Object c(com.google.android.gms.tasks.m mVar, C4003z frame) throws Exception {
        if (!mVar.k()) {
            C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
            c5028l.r();
            mVar.b(kotlinx.coroutines.tasks.a.a, new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(c5028l, 14));
            Object objQ = c5028l.q();
            if (objQ == kotlin.coroutines.intrinsics.a.a) {
                Intrinsics.checkNotNullParameter(frame, "frame");
            }
            return objQ;
        }
        Exception excG = mVar.g();
        if (excG != null) {
            throw excG;
        }
        if (!mVar.d) {
            return mVar.h();
        }
        throw new CancellationException("Task " + mVar + " was cancelled normally.");
    }

    public static final com.quizlet.features.infra.basestudy.ui.models.a d(com.quizlet.features.practicetest.common.data.h hVar, InterfaceC0806l interfaceC0806l) {
        com.quizlet.features.infra.basestudy.ui.models.a aVar;
        com.quizlet.features.infra.basestudy.ui.models.a aVar2;
        Intrinsics.checkNotNullParameter(hVar, "<this>");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1707330980);
        if (hVar.equals(com.quizlet.features.practicetest.common.data.e.a)) {
            c0814p.X(1273022185);
            aVar2 = new com.quizlet.features.infra.basestudy.ui.models.a(AbstractC3106b5.d(c0814p, R.string.practice_test_private_title), AbstractC3106b5.c(R.string.practice_test_private_description_combined, new Object[]{AbstractC3106b5.d(c0814p, R.string.practice_test_private_description), AbstractC3106b5.d(c0814p, R.string.help_center)}, c0814p), com.quizlet.themes.e.a(c0814p).d.y(c0814p), AbstractC3106b5.d(c0814p, R.string.practice_test_private_icon_description), null, null, 48);
            c0814p.p(false);
        } else {
            if (hVar instanceof com.quizlet.features.practicetest.common.data.b) {
                c0814p.X(1426559695);
                String strD = AbstractC3106b5.d(c0814p, R.string.practice_test_load_practice_test_error_title);
                String strD2 = AbstractC3106b5.d(c0814p, R.string.practice_test_load_error_description);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                aVar = new com.quizlet.features.infra.basestudy.ui.models.a(strD, strD2, androidx.compose.animation.core.J0.w(c0814p), AbstractC3106b5.d(c0814p, R.string.practice_test_error_icon_description), AbstractC3106b5.d(c0814p, R.string.practice_test_refresh_button), ((com.quizlet.features.practicetest.common.data.b) hVar).a);
                c0814p.p(false);
            } else if (hVar instanceof com.quizlet.features.practicetest.common.data.c) {
                c0814p.X(1426576558);
                String strD3 = AbstractC3106b5.d(c0814p, R.string.practice_test_load_question_bank_error_title);
                String strD4 = AbstractC3106b5.d(c0814p, R.string.practice_test_load_error_description);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                aVar = new com.quizlet.features.infra.basestudy.ui.models.a(strD3, strD4, androidx.compose.animation.core.J0.w(c0814p), AbstractC3106b5.d(c0814p, R.string.practice_test_error_icon_description), AbstractC3106b5.d(c0814p, R.string.practice_test_refresh_button), ((com.quizlet.features.practicetest.common.data.c) hVar).a);
                c0814p.p(false);
            } else if (hVar instanceof com.quizlet.features.practicetest.common.data.d) {
                c0814p.X(1426593026);
                String strD5 = AbstractC3106b5.d(c0814p, R.string.practice_test_no_internet_title);
                String strD6 = AbstractC3106b5.d(c0814p, R.string.practice_test_no_internet_description);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                aVar = new com.quizlet.features.infra.basestudy.ui.models.a(strD5, strD6, androidx.compose.animation.core.J0.w(c0814p), AbstractC3106b5.d(c0814p, R.string.practice_test_error_icon_description), AbstractC3106b5.d(c0814p, R.string.practice_test_refresh_button), ((com.quizlet.features.practicetest.common.data.d) hVar).a);
                c0814p.p(false);
            } else if (hVar.equals(com.quizlet.features.practicetest.common.data.g.a)) {
                c0814p.X(1426609016);
                String strD7 = AbstractC3106b5.d(c0814p, R.string.practice_test_user_ineligible_title);
                String strD8 = AbstractC3106b5.d(c0814p, R.string.help_center);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                aVar = new com.quizlet.features.infra.basestudy.ui.models.a(strD7, strD8, androidx.compose.animation.core.J0.w(c0814p), AbstractC3106b5.d(c0814p, R.string.practice_test_error_icon_description), null, null, 48);
                c0814p.p(false);
            } else {
                if (!(hVar instanceof com.quizlet.features.practicetest.common.data.f)) {
                    throw com.google.android.gms.measurement.internal.Z.j(1426539384, c0814p, false);
                }
                c0814p.X(1426621284);
                String strD9 = AbstractC3106b5.d(c0814p, R.string.practice_test_unsupported_question_bank_title);
                String strD10 = AbstractC3106b5.d(c0814p, R.string.practice_test_unsupported_question_bank_description);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                aVar = new com.quizlet.features.infra.basestudy.ui.models.a(strD9, strD10, androidx.compose.animation.core.J0.w(c0814p), AbstractC3106b5.d(c0814p, R.string.practice_test_error_icon_description), AbstractC3106b5.d(c0814p, R.string.practice_test_open_browser_button), ((com.quizlet.features.practicetest.common.data.f) hVar).a);
                c0814p.p(false);
            }
            aVar2 = aVar;
        }
        c0814p.p(false);
        return aVar2;
    }
}
