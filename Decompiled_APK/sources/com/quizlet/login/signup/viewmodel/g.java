package com.quizlet.login.signup.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.w0;
import com.features.flashcards.creatormarketing.h;
import com.google.android.gms.internal.mlkit_common.u;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.login.common.interactors.data.C4590a;
import com.quizlet.login.common.interactors.data.C4591b;
import com.quizlet.login.common.interactors.data.i;
import com.quizlet.login.common.interactors.data.w;
import com.quizlet.login.common.interactors.data.x;
import com.quizlet.login.common.interactors.data.z;
import com.quizlet.login.signup.data.r;
import java.time.LocalDate;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class g extends w0 implements a {
    public final h b;
    public final com.onetrust.otpublishers.headless.UI.TVUI.datautils.d c;
    public final com.quizlet.login.common.interactors.d d;
    public final androidx.work.impl.model.c e;
    public final q f;
    public final s0 g;
    public final d0 h;
    public final boolean i;

    public g(h signUpLoginEventLogger, com.onetrust.otpublishers.headless.UI.TVUI.datautils.d signUpWithEmailAndPasswordUseCase, com.quizlet.login.common.interactors.d emailValidationUseCase, androidx.work.impl.model.c dateOfBirthValidationUseCase, q isOverTwentyOneUseCase, u getSelectableCalendarDataUseCase, m0 savedStateHandle) {
        Intrinsics.checkNotNullParameter(signUpLoginEventLogger, "signUpLoginEventLogger");
        Intrinsics.checkNotNullParameter(signUpWithEmailAndPasswordUseCase, "signUpWithEmailAndPasswordUseCase");
        Intrinsics.checkNotNullParameter(emailValidationUseCase, "emailValidationUseCase");
        Intrinsics.checkNotNullParameter(dateOfBirthValidationUseCase, "dateOfBirthValidationUseCase");
        Intrinsics.checkNotNullParameter(isOverTwentyOneUseCase, "isOverTwentyOneUseCase");
        Intrinsics.checkNotNullParameter(getSelectableCalendarDataUseCase, "getSelectableCalendarDataUseCase");
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        this.b = signUpLoginEventLogger;
        this.c = signUpWithEmailAndPasswordUseCase;
        this.d = emailValidationUseCase;
        this.e = dateOfBirthValidationUseCase;
        this.f = isOverTwentyOneUseCase;
        long jCurrentTimeMillis = System.currentTimeMillis();
        LocalDate localDateNow = LocalDate.now();
        Intrinsics.checkNotNullExpressionValue(localDateNow, "now(...)");
        this.g = e0.c(new r(false, new C4590a(localDateNow.getYear(), jCurrentTimeMillis), false, null, i.a, C4591b.a));
        this.h = e0.b(0, 1, null, 5);
        Boolean bool = (Boolean) savedStateHandle.a("shouldSkipUpsell");
        this.i = bool != null ? bool.booleanValue() : false;
    }

    public static final void A(g gVar, z zVar) {
        s0 s0Var;
        Object value;
        gVar.getClass();
        if ((zVar instanceof w) || (zVar instanceof x)) {
            return;
        }
        do {
            s0Var = gVar.g;
            value = s0Var.getValue();
        } while (!s0Var.k(value, r.a((r) value, false, false, null, null, null, 62)));
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object B(com.quizlet.login.signup.viewmodel.g r7, java.lang.String r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r7.getClass()
            boolean r0 = r9 instanceof com.quizlet.login.signup.viewmodel.f
            if (r0 == 0) goto L16
            r0 = r9
            com.quizlet.login.signup.viewmodel.f r0 = (com.quizlet.login.signup.viewmodel.f) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.login.signup.viewmodel.f r0 = new com.quizlet.login.signup.viewmodel.f
            r0.<init>(r7, r9)
        L1b:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            com.quizlet.login.signup.viewmodel.g r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L44
        L2c:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r7
            r0.m = r3
            com.quizlet.login.common.interactors.d r9 = r7.d
            java.lang.Object r9 = r9.k(r8, r0)
            if (r9 != r1) goto L44
            return r1
        L44:
            r4 = r9
            com.quizlet.login.common.interactors.data.j r4 = (com.quizlet.login.common.interactors.data.j) r4
            kotlinx.coroutines.flow.s0 r7 = r7.g
        L49:
            java.lang.Object r8 = r7.getValue()
            r0 = r8
            com.quizlet.login.signup.data.r r0 = (com.quizlet.login.signup.data.r) r0
            r2 = 0
            r6 = 47
            r1 = 0
            r3 = 0
            r5 = 0
            com.quizlet.login.signup.data.r r9 = com.quizlet.login.signup.data.r.a(r0, r1, r2, r3, r4, r5, r6)
            boolean r8 = r7.k(r8, r9)
            if (r8 == 0) goto L49
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.signup.viewmodel.g.B(com.quizlet.login.signup.viewmodel.g, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void C(boolean z) {
        s0 s0Var;
        Object value;
        if (z) {
            do {
                s0Var = this.g;
                value = s0Var.getValue();
            } while (!s0Var.k(value, r.a((r) value, false, false, com.quizlet.login.authentication.h.c, null, null, 55)));
        }
    }
}
