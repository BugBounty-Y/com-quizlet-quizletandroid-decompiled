package com.quizlet.login.magiclink.viewmodel;

import androidx.lifecycle.w0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class j extends w0 implements b {
    public final com.quizlet.qutils.string.c b;
    public final com.quizlet.data.interactor.course.a c;
    public final s0 d;
    public final d0 e;

    public j(com.quizlet.data.interactor.course.a sendMagicLinkUseCase) {
        com.quizlet.qutils.string.c emailUtil = com.quizlet.qutils.string.c.a;
        Intrinsics.checkNotNullParameter(emailUtil, "emailUtil");
        Intrinsics.checkNotNullParameter(sendMagicLinkUseCase, "sendMagicLinkUseCase");
        this.b = emailUtil;
        this.c = sendMagicLinkUseCase;
        this.d = e0.c(com.quizlet.login.magiclink.data.i.a);
        this.e = e0.b(0, 1, null, 5);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object A(java.lang.String r6, kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            r5 = this;
            boolean r0 = r7 instanceof com.quizlet.login.magiclink.viewmodel.h
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.login.magiclink.viewmodel.h r0 = (com.quizlet.login.magiclink.viewmodel.h) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.login.magiclink.viewmodel.h r0 = new com.quizlet.login.magiclink.viewmodel.h
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L49
        L27:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.l = r3
            com.quizlet.data.interactor.course.a r7 = r5.c
            java.lang.Object r7 = r7.b
            com.quizlet.remote.model.login.magiclink.b r7 = (com.quizlet.remote.model.login.magiclink.b) r7
            com.quizlet.remote.model.login.magiclink.a r2 = new com.quizlet.remote.model.login.magiclink.a
            r4 = 0
            r2.<init>(r7, r6, r4)
            kotlinx.coroutines.y r6 = r7.b
            java.lang.Object r7 = kotlinx.coroutines.E.J(r6, r2, r0)
            if (r7 != r1) goto L49
            return r1
        L49:
            com.quizlet.data.model.G1 r7 = (com.quizlet.data.model.G1) r7
            int r6 = r7.ordinal()
            if (r6 == 0) goto L82
            if (r6 == r3) goto L7a
            r7 = 2
            if (r6 == r7) goto L72
            r7 = 3
            if (r6 == r7) goto L6a
            r7 = 4
            if (r6 != r7) goto L64
            com.quizlet.login.magiclink.data.h r6 = new com.quizlet.login.magiclink.data.h
            com.quizlet.login.magiclink.data.f r7 = com.quizlet.login.magiclink.data.f.a
            r6.<init>(r7)
            return r6
        L64:
            kotlin.NoWhenBranchMatchedException r6 = new kotlin.NoWhenBranchMatchedException
            r6.<init>()
            throw r6
        L6a:
            com.quizlet.login.magiclink.data.h r6 = new com.quizlet.login.magiclink.data.h
            com.quizlet.login.magiclink.data.d r7 = com.quizlet.login.magiclink.data.d.a
            r6.<init>(r7)
            return r6
        L72:
            com.quizlet.login.magiclink.data.h r6 = new com.quizlet.login.magiclink.data.h
            com.quizlet.login.magiclink.data.b r7 = com.quizlet.login.magiclink.data.b.a
            r6.<init>(r7)
            return r6
        L7a:
            com.quizlet.login.magiclink.data.h r6 = new com.quizlet.login.magiclink.data.h
            com.quizlet.login.magiclink.data.c r7 = com.quizlet.login.magiclink.data.c.a
            r6.<init>(r7)
            return r6
        L82:
            com.quizlet.login.magiclink.data.j r6 = com.quizlet.login.magiclink.data.j.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.magiclink.viewmodel.j.A(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
