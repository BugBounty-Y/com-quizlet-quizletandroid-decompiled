package com.quizlet.data.repository.term;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes2.dex */
public final class g {
    public final com.quizlet.data.repository.set.f a;
    public final com.quizlet.data.repository.classfolder.e b;
    public final com.quizlet.data.connectivity.a c;
    public final AbstractC5040y d;
    public final org.slf4j.b e;

    public g(com.quizlet.data.repository.set.f local, com.quizlet.data.repository.classfolder.e remote, com.quizlet.data.connectivity.a networkStatus, AbstractC5040y ioDispatcher, org.slf4j.b logger) {
        Intrinsics.checkNotNullParameter(local, "local");
        Intrinsics.checkNotNullParameter(remote, "remote");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.a = local;
        this.b = remote;
        this.c = networkStatus;
        this.d = ioDispatcher;
        this.e = logger;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.quizlet.data.repository.term.g r10, long r11, com.quizlet.data.model.J0 r13, kotlin.coroutines.jvm.internal.c r14) {
        /*
            boolean r0 = r14 instanceof com.quizlet.data.repository.term.b
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.data.repository.term.b r0 = (com.quizlet.data.repository.term.b) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.repository.term.b r0 = new com.quizlet.data.repository.term.b
            r0.<init>(r10, r14)
        L18:
            java.lang.Object r14 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L46
        L27:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            com.quizlet.data.repository.term.c r4 = new com.quizlet.data.repository.term.c
            r9 = 0
            r5 = r10
            r6 = r11
            r8 = r13
            r4.<init>(r5, r6, r8, r9)
            r0.l = r3
            kotlinx.coroutines.y r10 = r5.d
            java.lang.Object r14 = kotlinx.coroutines.E.J(r10, r4, r0)
            if (r14 != r1) goto L46
            return r1
        L46:
            kotlin.r r14 = (kotlin.r) r14
            java.lang.Object r10 = r14.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.term.g.a(com.quizlet.data.repository.term.g, long, com.quizlet.data.model.J0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
