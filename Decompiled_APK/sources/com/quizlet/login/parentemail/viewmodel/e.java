package com.quizlet.login.parentemail.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.w0;
import com.quizlet.data.repository.achievements.h;
import com.quizlet.login.common.interactors.data.i;
import com.quizlet.login.parentemail.data.o;
import com.quizlet.login.signup.data.PromptParentEmailData;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class e extends w0 implements a {
    public final h b;
    public final com.quizlet.login.common.interactors.d c;
    public final s0 d;
    public final d0 e;
    public final PromptParentEmailData f;
    public final boolean g;

    public e(m0 savedStateHandle, h signUpWithParentEmailUseCase, com.quizlet.login.common.interactors.d emailValidationUseCase) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(signUpWithParentEmailUseCase, "signUpWithParentEmailUseCase");
        Intrinsics.checkNotNullParameter(emailValidationUseCase, "emailValidationUseCase");
        this.b = signUpWithParentEmailUseCase;
        this.c = emailValidationUseCase;
        this.d = e0.c(new o(false, null, i.a));
        this.e = e0.b(0, 1, null, 5);
        this.f = (PromptParentEmailData) savedStateHandle.a("parentEmailData");
        Boolean bool = (Boolean) savedStateHandle.a("shouldSkipUpsell");
        this.g = bool != null ? bool.booleanValue() : false;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.login.parentemail.viewmodel.e r4, java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) throws java.lang.Throwable {
        /*
            r4.getClass()
            boolean r0 = r6 instanceof com.quizlet.login.parentemail.viewmodel.d
            if (r0 == 0) goto L16
            r0 = r6
            com.quizlet.login.parentemail.viewmodel.d r0 = (com.quizlet.login.parentemail.viewmodel.d) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.login.parentemail.viewmodel.d r0 = new com.quizlet.login.parentemail.viewmodel.d
            r0.<init>(r4, r6)
        L1b:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            com.quizlet.login.parentemail.viewmodel.e r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L44
        L2c:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.m = r3
            com.quizlet.login.common.interactors.d r6 = r4.c
            java.lang.Object r6 = r6.k(r5, r0)
            if (r6 != r1) goto L44
            return r1
        L44:
            com.quizlet.login.common.interactors.data.j r6 = (com.quizlet.login.common.interactors.data.j) r6
            kotlinx.coroutines.flow.s0 r4 = r4.d
        L48:
            java.lang.Object r5 = r4.getValue()
            r0 = r5
            com.quizlet.login.parentemail.data.o r0 = (com.quizlet.login.parentemail.data.o) r0
            r1 = 0
            r2 = 3
            r3 = 0
            com.quizlet.login.parentemail.data.o r0 = com.quizlet.login.parentemail.data.o.a(r0, r3, r1, r6, r2)
            boolean r5 = r4.k(r5, r0)
            if (r5 == 0) goto L48
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.parentemail.viewmodel.e.A(com.quizlet.login.parentemail.viewmodel.e, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
