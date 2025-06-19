package com.quizlet.data.repository.selectedterm;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes2.dex */
public final class f {
    public final com.quizlet.data.interactor.set.c a;
    public final com.quizlet.data.repository.login.a b;
    public final AbstractC5040y c;
    public final org.slf4j.b d;

    public f(com.quizlet.data.interactor.set.c remote, com.quizlet.data.repository.login.a local, AbstractC5040y ioDispatcher, org.slf4j.b logger) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        Intrinsics.checkNotNullParameter(local, "local");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.a = remote;
        this.b = local;
        this.c = ioDispatcher;
        this.d = logger;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.quizlet.data.repository.selectedterm.f r11, long r12, long r14, com.quizlet.data.model.J0 r16, kotlin.coroutines.jvm.internal.c r17) {
        /*
            r0 = r17
            boolean r2 = r0 instanceof com.quizlet.data.repository.selectedterm.a
            if (r2 == 0) goto L16
            r2 = r0
            com.quizlet.data.repository.selectedterm.a r2 = (com.quizlet.data.repository.selectedterm.a) r2
            int r3 = r2.l
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L16
            int r3 = r3 - r4
            r2.l = r3
        L14:
            r8 = r2
            goto L1c
        L16:
            com.quizlet.data.repository.selectedterm.a r2 = new com.quizlet.data.repository.selectedterm.a
            r2.<init>(r11, r0)
            goto L14
        L1c:
            java.lang.Object r0 = r8.j
            kotlin.coroutines.intrinsics.a r9 = kotlin.coroutines.intrinsics.a.a
            int r2 = r8.l
            r10 = 1
            if (r2 == 0) goto L33
            if (r2 != r10) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L4c
        L2b:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.quizlet.data.repository.selectedterm.b r0 = new com.quizlet.data.repository.selectedterm.b
            r7 = 0
            r1 = r11
            r2 = r12
            r4 = r14
            r6 = r16
            r0.<init>(r1, r2, r4, r6, r7)
            r8.l = r10
            kotlinx.coroutines.y r1 = r11.c
            java.lang.Object r0 = kotlinx.coroutines.E.J(r1, r0, r8)
            if (r0 != r9) goto L4c
            return r9
        L4c:
            kotlin.r r0 = (kotlin.r) r0
            java.lang.Object r0 = r0.a
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.selectedterm.f.a(com.quizlet.data.repository.selectedterm.f, long, long, com.quizlet.data.model.J0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
