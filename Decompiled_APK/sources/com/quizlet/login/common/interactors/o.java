package com.quizlet.login.common.interactors;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes3.dex */
public final class o {
    public final io.ktor.client.plugins.api.d a;
    public final com.quizlet.qutils.string.c b;
    public final androidx.compose.runtime.internal.j c;
    public final AbstractC5040y d;

    public o(io.ktor.client.plugins.api.d loginApiClientManager, com.quizlet.qutils.string.c state, androidx.compose.runtime.internal.j handleLoginResponseUseCase, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(loginApiClientManager, "loginApiClientManager");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(handleLoginResponseUseCase, "handleLoginResponseUseCase");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = loginApiClientManager;
        this.b = state;
        this.c = handleLoginResponseUseCase;
        this.d = ioDispatcher;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(java.lang.String r7, kotlin.coroutines.jvm.internal.c r8) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.login.common.interactors.m
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.login.common.interactors.m r0 = (com.quizlet.login.common.interactors.m) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.login.common.interactors.m r0 = new com.quizlet.login.common.interactors.m
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L39
            if (r2 == r5) goto L33
            if (r2 != r4) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r8)
            return r8
        L2b:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L33:
            com.quizlet.login.common.interactors.o r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L4f
        L39:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.login.common.interactors.n r8 = new com.quizlet.login.common.interactors.n
            r8.<init>(r7, r6, r3)
            r0.j = r6
            r0.m = r5
            kotlinx.coroutines.y r7 = r6.d
            java.lang.Object r8 = kotlinx.coroutines.E.J(r7, r8, r0)
            if (r8 != r1) goto L4e
            goto L64
        L4e:
            r7 = r6
        L4f:
            java.lang.String r2 = "withContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r2)
            com.quizlet.login.authentication.data.i r8 = (com.quizlet.login.authentication.data.i) r8
            androidx.compose.runtime.internal.j r7 = r7.c
            r0.j = r3
            r0.m = r4
            java.lang.String r2 = "email"
            java.lang.Object r7 = r7.s(r8, r2, r3, r0)
            if (r7 != r1) goto L65
        L64:
            return r1
        L65:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.common.interactors.o.a(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
