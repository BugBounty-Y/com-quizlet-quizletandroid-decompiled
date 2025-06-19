package com.quizlet.features.emailconfirmation.ui.composables;

import android.content.Context;
import androidx.activity.K;
import androidx.compose.material3.O3;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.lifecycle.J;
import androidx.navigation.compose.C1278k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3307y6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3315z6;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes2.dex */
public abstract class y {
    static {
        s userType = (6 & 2) != 0 ? s.a : null;
        Intrinsics.checkNotNullParameter("email@email.com", "email");
        Intrinsics.checkNotNullParameter(userType, "userType");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void a(com.quizlet.features.emailconfirmation.viewmodel.g viewModel, InterfaceC0806l interfaceC0806l, int i) {
        Object cVar;
        Unit unit;
        AbstractC0809m0 abstractC0809m0;
        kotlin.coroutines.h hVar;
        com.quizlet.features.infra.logout.composables.a aVar;
        boolean z;
        O3 o3;
        V v;
        int i2;
        boolean z2;
        com.quizlet.features.emailconfirmation.viewmodel.g gVar;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-2140589701);
        int i3 = (c0814p2.f(viewModel) ? 4 : 2) | i;
        if ((i3 & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            gVar = viewModel;
            c0814p = c0814p2;
        } else {
            com.quizlet.features.emailconfirmation.viewmodel.f fVar = (com.quizlet.features.emailconfirmation.viewmodel.f) viewModel;
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(fVar.f, c0814p2);
            com.quizlet.features.infra.logout.composables.a aVarA = AbstractC3307y6.a(c0814p2);
            c0814p2.X(1458744628);
            Object objI = c0814p2.I();
            V v2 = C0804k.a;
            if (objI == v2) {
                objI = new O3();
                c0814p2.i0(objI);
            }
            O3 o32 = (O3) objI;
            c0814p2.p(false);
            Context context = (Context) c0814p2.j(AndroidCompositionLocals_androidKt.b);
            d0 d0Var = fVar.h;
            c0814p2.X(1458748752);
            boolean zH = c0814p2.h(context);
            Object objI2 = c0814p2.I();
            if (zH || objI2 == v2) {
                objI2 = new x(o32, context, null);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            c0814p2.X(-827048655);
            AbstractC0809m0 abstractC0809m02 = androidx.lifecycle.compose.g.a;
            J j = (J) c0814p2.j(abstractC0809m02);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p2);
            Unit unit2 = Unit.a;
            c0814p2.X(1667431386);
            boolean zH2 = c0814p2.h(j) | c0814p2.h(d0Var) | c0814p2.f(b) | c0814p2.f(interfaceC0773a0D);
            Object objI3 = c0814p2.I();
            if (zH2 || objI3 == v2) {
                objI3 = new u(interfaceC0773a0D, j, null, d0Var);
                c0814p2.i0(objI3);
            }
            c0814p2.p(false);
            C0776c.f(c0814p2, unit2, (Function2) objI3);
            c0814p2.p(false);
            d0 d0Var2 = fVar.d.f;
            c0814p2.X(1458753693);
            boolean zH3 = c0814p2.h(aVarA);
            Object objI4 = c0814p2.I();
            if (zH3 || objI4 == v2) {
                unit = unit2;
                abstractC0809m0 = abstractC0809m02;
                hVar = null;
                cVar = new androidx.compose.runtime.internal.c(2, aVarA, com.quizlet.features.infra.logout.composables.a.class, "showLogOutWarningModal", "showLogOutWarningModal(Lcom/quizlet/data/model/LogoutWarning;)V", 4, 2);
                aVar = aVarA;
                c0814p2.i0(cVar);
            } else {
                cVar = objI4;
                unit = unit2;
                aVar = aVarA;
                hVar = null;
                abstractC0809m0 = abstractC0809m02;
            }
            c0814p2.p(false);
            c0814p2.X(-827048655);
            J j2 = (J) c0814p2.j(abstractC0809m0);
            InterfaceC0773a0 interfaceC0773a0D2 = C0776c.D((Function2) cVar, c0814p2);
            c0814p2.X(1667431386);
            boolean zF = c0814p2.f(b) | c0814p2.h(j2) | c0814p2.h(d0Var2) | c0814p2.f(interfaceC0773a0D2);
            Object objI5 = c0814p2.I();
            if (zF || objI5 == v2) {
                objI5 = new w(interfaceC0773a0D2, j2, hVar, d0Var2);
                c0814p2.i0(objI5);
            }
            c0814p2.p(false);
            com.quizlet.features.emailconfirmation.data.states.a aVar2 = (com.quizlet.features.emailconfirmation.data.states.a) AbstractC4178x.k(unit, (Function2) objI5, c0814p2, false, interfaceC0773a0M);
            c0814p2.X(1081821326);
            String str = aVar2.a;
            String strD = AbstractC3106b5.d(c0814p2, R.string.resend_confirmation_email_button);
            c0814p2.X(-1233751570);
            String strD2 = aVar2.b == s.a ? AbstractC3106b5.d(c0814p2, R.string.update_email_button) : hVar;
            c0814p2.p(false);
            r rVar = new r(str, aVar2.b, aVar2.c, strD, strD2, AbstractC3106b5.d(c0814p2, R.string.logout));
            c0814p2.p(false);
            c0814p2.X(1458759672);
            int i4 = i3 & 14;
            boolean z3 = i4 == 4;
            Object objI6 = c0814p2.I();
            if (z3 || objI6 == v2) {
                z = false;
                o3 = o32;
                v = v2;
                K k = new K(0, viewModel, com.quizlet.features.emailconfirmation.viewmodel.g.class, "onResendConfirmationClick", "onResendConfirmationClick()V", 0, 25);
                c0814p2.i0(k);
                objI6 = k;
            } else {
                z = false;
                o3 = o32;
                v = v2;
            }
            c0814p2.p(z);
            Function0 function0 = (Function0) ((kotlin.reflect.f) objI6);
            c0814p2.X(1458761841);
            boolean z4 = i4 != 4 ? z : true;
            Object objI7 = c0814p2.I();
            if (z4 || objI7 == v) {
                objI7 = new K(0, viewModel, com.quizlet.features.emailconfirmation.viewmodel.g.class, "onUpdateEmailClick", "onUpdateEmailClick()V", 0, 26);
                c0814p2.i0(objI7);
            }
            c0814p2.p(z);
            Function0 function02 = (Function0) ((kotlin.reflect.f) objI7);
            c0814p2.X(1458763756);
            boolean z5 = i4 != 4 ? z : true;
            Object objI8 = c0814p2.I();
            if (z5 || objI8 == v) {
                i2 = 4;
                K k2 = new K(0, viewModel, com.quizlet.features.emailconfirmation.viewmodel.g.class, "onLogOutClick", "onLogOutClick()V", 0, 27);
                c0814p2.i0(k2);
                objI8 = k2;
            } else {
                i2 = 4;
            }
            c0814p2.p(z);
            boolean z6 = z;
            V v3 = v;
            int i5 = i2;
            q.a(rVar, null, o3, function0, function02, (Function0) ((kotlin.reflect.f) objI8), 0L, c0814p2, 384, 66);
            c0814p2.X(1458767600);
            boolean z7 = i4 != i5 ? z6 : true;
            Object objI9 = c0814p2.I();
            if (z7 || objI9 == v3) {
                z2 = z6;
                objI9 = new com.quizlet.explanations.textbook.ui.f(1, viewModel, com.quizlet.features.emailconfirmation.viewmodel.g.class, "onLogOutConfirmed", "onLogOutConfirmed(Lcom/quizlet/data/model/LogoutWarning;)V", 0, 5);
                gVar = viewModel;
                c0814p2.i0(objI9);
            } else {
                gVar = viewModel;
                z2 = z6;
            }
            c0814p2.p(z2);
            c0814p = c0814p2;
            AbstractC3315z6.a(aVar, (Function1) ((kotlin.reflect.f) objI9), null, c0814p, 8, 4);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(gVar, i, 9);
        }
    }
}
