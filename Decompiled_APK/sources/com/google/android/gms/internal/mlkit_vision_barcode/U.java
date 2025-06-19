package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.navigation.compose.C1278k;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Collection;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class U {
    public static final void a(com.quizlet.features.emailconfirmation.viewmodel.h hVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Object viewModel = hVar;
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(675926800);
        int i2 = (c0814p2.f(viewModel) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            com.quizlet.features.emailconfirmation.viewmodel.m mVar = (com.quizlet.features.emailconfirmation.viewmodel.m) viewModel;
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(mVar.f, c0814p2);
            c0814p2.X(-390698945);
            Object objI = c0814p2.I();
            Object obj = C0804k.a;
            if (objI == obj) {
                objI = new androidx.compose.material3.O3();
                c0814p2.i0(objI);
            }
            androidx.compose.material3.O3 o3 = (androidx.compose.material3.O3) objI;
            c0814p2.p(false);
            Context context = (Context) c0814p2.j(AndroidCompositionLocals_androidKt.b);
            kotlinx.coroutines.flow.d0 d0Var = mVar.h;
            c0814p2.X(-390695057);
            boolean zH = c0814p2.h(context);
            Object objI2 = c0814p2.I();
            if (zH || objI2 == obj) {
                objI2 = new com.quizlet.features.emailconfirmation.ui.composables.B(o3, context, null);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            c0814p2.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p2.j(androidx.lifecycle.compose.g.a);
            Object obj2 = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p2);
            Unit unit = Unit.a;
            c0814p2.X(1667431386);
            boolean zF = c0814p2.f(obj2) | c0814p2.h(j) | c0814p2.h(d0Var) | c0814p2.f(interfaceC0773a0D);
            Object objI3 = c0814p2.I();
            if (zF || objI3 == obj) {
                objI3 = new com.quizlet.features.emailconfirmation.ui.composables.A(interfaceC0773a0D, j, null, d0Var);
                c0814p2.i0(objI3);
            }
            c0814p2.p(false);
            com.quizlet.features.emailconfirmation.data.states.a aVar = (com.quizlet.features.emailconfirmation.data.states.a) AbstractC4178x.k(unit, (Function2) objI3, c0814p2, false, interfaceC0773a0M);
            c0814p2.X(-820173885);
            com.quizlet.features.emailconfirmation.ui.composables.r rVar = new com.quizlet.features.emailconfirmation.ui.composables.r(aVar.a, aVar.b, aVar.c, AbstractC3106b5.d(c0814p2, R.string.resend_confirmation_email_button), AbstractC3106b5.d(c0814p2, R.string.create_new_account_button), 32);
            c0814p2.p(false);
            c0814p2.X(-390687933);
            int i3 = i2 & 14;
            boolean z = i3 == 4;
            Object objI4 = c0814p2.I();
            if (z || objI4 == obj) {
                Object k = new androidx.activity.K(0, viewModel, com.quizlet.features.emailconfirmation.viewmodel.h.class, "onResendConfirmationClick", "onResendConfirmationClick()V", 0, 28);
                c0814p2.i0(k);
                objI4 = k;
            }
            c0814p2.p(false);
            Function0 function0 = (Function0) ((kotlin.reflect.f) objI4);
            c0814p2.X(-390685759);
            boolean z2 = i3 == 4;
            Object objI5 = c0814p2.I();
            if (z2 || objI5 == obj) {
                viewModel = hVar;
                objI5 = new androidx.activity.K(0, viewModel, com.quizlet.features.emailconfirmation.viewmodel.h.class, "onCreateNewAccountClick", "onCreateNewAccountClick()V", 0, 29);
                c0814p2.i0(objI5);
            } else {
                viewModel = hVar;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            com.quizlet.features.emailconfirmation.ui.composables.q.a(rVar, null, o3, function0, (Function0) ((kotlin.reflect.f) objI5), null, 0L, c0814p, 384, 98);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(viewModel, i, 10);
        }
    }

    public static String b(int i) {
        ArrayList arrayList = new ArrayList();
        if ((i & 4) != 0) {
            arrayList.add("IMAGE_CAPTURE");
        }
        if ((i & 1) != 0) {
            arrayList.add("PREVIEW");
        }
        if ((i & 2) != 0) {
            arrayList.add("VIDEO_CAPTURE");
        }
        return String.join("|", arrayList);
    }

    public static final String c(Collection collection) {
        Intrinsics.checkNotNullParameter(collection, "<this>");
        return CollectionsKt.S(collection, ",", null, null, null, 62);
    }
}
