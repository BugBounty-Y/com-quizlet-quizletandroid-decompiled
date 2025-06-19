package com.google.android.gms.internal.mlkit_vision_barcode;

import android.util.Log;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0995g;
import androidx.fragment.app.Fragment;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3667l6;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class J6 {
    public static final void a(androidx.compose.material3.L3 snackbarData, com.quizlet.features.infra.snackbar.composables.a visuals, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(snackbarData, "snackbarData");
        Intrinsics.checkNotNullParameter(visuals, "visuals");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1740610707);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(snackbarData) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(visuals) ? 32 : 16;
        }
        int i3 = i2 | 384;
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            qVar = androidx.compose.ui.n.b;
            com.quizlet.qutils.string.g gVar = visuals.a.c;
            c0814p.X(578758434);
            String strB = gVar.b(c0814p);
            c0814p.p(false);
            if (strB == null) {
                strB = "";
            }
            com.quizlet.themes.m.g.s();
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVar, com.quizlet.ui.resources.designsystem.generated.j.h);
            C0995g c0995g = new C0995g(6, strB, null);
            com.quizlet.qutils.string.g gVar2 = visuals.a.d;
            c0814p.X(578765154);
            String strB2 = gVar2 != null ? gVar2.b(c0814p) : null;
            c0814p.p(false);
            c0814p.X(578766457);
            boolean z = ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i3 & 14) == 4);
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new com.quizlet.data.repository.explanations.exercise.a(20, visuals, snackbarData);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3667l6.c(c0995g, qVarU, strB2, (Function0) objI, null, null, c0814p, 0, 104);
        }
        androidx.compose.ui.q qVar2 = qVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 15, snackbarData, visuals, qVar2);
        }
    }

    public static androidx.datastore.b b(String fileName, androidx.datastore.core.f0 serializer, com.airbnb.lottie.network.c cVar) {
        androidx.datastore.a produceMigrations = androidx.datastore.a.a;
        kotlinx.coroutines.scheduling.e eVar = kotlinx.coroutines.O.a;
        kotlinx.coroutines.internal.d scope = kotlinx.coroutines.E.c(kotlinx.coroutines.scheduling.d.b.plus(kotlinx.coroutines.E.e()));
        Intrinsics.checkNotNullParameter(fileName, "fileName");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        Intrinsics.checkNotNullParameter(produceMigrations, "produceMigrations");
        Intrinsics.checkNotNullParameter(scope, "scope");
        return new androidx.datastore.b(fileName, new com.quizlet.data.repository.school.membership.a(serializer), cVar, scope);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static void c(Fragment fragment) {
        dagger.android.c cVar;
        Fragment parentFragment = fragment;
        while (true) {
            parentFragment = parentFragment.getParentFragment();
            if (parentFragment == 0) {
                androidx.fragment.app.I activity = fragment.getActivity();
                if (activity instanceof dagger.android.c) {
                    cVar = (dagger.android.c) activity;
                } else {
                    if (!(activity.getApplication() instanceof dagger.android.c)) {
                        throw new IllegalArgumentException(AbstractC0147y.d("No injector was found for ", fragment.getClass().getCanonicalName()));
                    }
                    cVar = (dagger.android.c) activity.getApplication();
                }
            } else if (parentFragment instanceof dagger.android.c) {
                cVar = (dagger.android.c) parentFragment;
                break;
            }
        }
        if (Log.isLoggable("dagger.android.support", 3)) {
            cVar.getClass();
        }
        C4636c c4636cC = cVar.c();
        S6.b(c4636cC, "%s.androidInjector() returned null", cVar.getClass());
        c4636cC.d(fragment);
    }
}
