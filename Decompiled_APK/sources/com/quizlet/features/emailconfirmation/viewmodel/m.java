package com.quizlet.features.emailconfirmation.viewmodel;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.quizlet.generated.enums.B;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes2.dex */
public final class m extends w0 implements h {
    public final com.lyft.android.scissors.b b;
    public final com.google.mlkit.vision.documentscanner.internal.c c;
    public final com.quizlet.data.interactor.course.a d;
    public final com.quizlet.features.emailconfirmation.logging.a e;
    public final s0 f;
    public final d0 g;
    public final d0 h;

    public m(com.lyft.android.scissors.b getCurrentConfirmationWallEmailUseCase, com.google.mlkit.vision.documentscanner.internal.c saveConfirmationWallEmailUseCase, com.quizlet.data.interactor.course.a sendMagicLinkUseCase, com.quizlet.features.emailconfirmation.logging.a logger) {
        Intrinsics.checkNotNullParameter(getCurrentConfirmationWallEmailUseCase, "getCurrentConfirmationWallEmailUseCase");
        Intrinsics.checkNotNullParameter(saveConfirmationWallEmailUseCase, "saveConfirmationWallEmailUseCase");
        Intrinsics.checkNotNullParameter(sendMagicLinkUseCase, "sendMagicLinkUseCase");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = getCurrentConfirmationWallEmailUseCase;
        this.c = saveConfirmationWallEmailUseCase;
        this.d = sendMagicLinkUseCase;
        this.e = logger;
        this.f = e0.c(new com.quizlet.features.emailconfirmation.data.states.a());
        this.g = e0.b(1, 1, null, 4);
        this.h = e0.b(0, 0, null, 7);
        logger.a(B.EMAIL_CONFIRMATION_SEEN);
        E.A(p0.j(this), null, null, new k(this, null), 3);
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x0083, code lost:
    
        if (r8.emit(r9, r0) == r1) goto L48;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x00b1, code lost:
    
        if (r8.emit(r9, r0) == r1) goto L48;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x00c3, code lost:
    
        if (r8.emit(r9, r0) == r1) goto L48;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.features.emailconfirmation.viewmodel.m r8, java.lang.String r9, kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            r8.getClass()
            boolean r0 = r10 instanceof com.quizlet.features.emailconfirmation.viewmodel.l
            if (r0 == 0) goto L16
            r0 = r10
            com.quizlet.features.emailconfirmation.viewmodel.l r0 = (com.quizlet.features.emailconfirmation.viewmodel.l) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.features.emailconfirmation.viewmodel.l r0 = new com.quizlet.features.emailconfirmation.viewmodel.l
            r0.<init>(r8, r10)
        L1b:
            java.lang.Object r10 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 3
            r4 = 0
            r5 = 4
            r6 = 2
            r7 = 1
            if (r2 == 0) goto L4c
            if (r2 == r7) goto L46
            if (r2 == r6) goto L41
            if (r2 == r3) goto L3c
            if (r2 != r5) goto L34
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L86
        L34:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto Lb4
        L41:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto Lc6
        L46:
            com.quizlet.features.emailconfirmation.viewmodel.m r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L67
        L4c:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            r0.j = r8
            r0.m = r7
            com.quizlet.data.interactor.course.a r10 = r8.d
            java.lang.Object r10 = r10.b
            com.quizlet.remote.model.login.magiclink.b r10 = (com.quizlet.remote.model.login.magiclink.b) r10
            com.quizlet.remote.model.login.magiclink.a r2 = new com.quizlet.remote.model.login.magiclink.a
            r2.<init>(r10, r9, r4)
            kotlinx.coroutines.y r9 = r10.b
            java.lang.Object r10 = kotlinx.coroutines.E.J(r9, r2, r0)
            if (r10 != r1) goto L67
            goto Lc5
        L67:
            com.quizlet.data.model.G1 r10 = (com.quizlet.data.model.G1) r10
            int r9 = r10.ordinal()
            if (r9 == 0) goto Lb7
            if (r9 == r7) goto La5
            if (r9 == r6) goto L8f
            if (r9 == r3) goto L8f
            if (r9 != r5) goto L89
            kotlinx.coroutines.flow.d0 r8 = r8.h
            com.quizlet.features.emailconfirmation.data.events.c r9 = com.quizlet.features.emailconfirmation.data.events.c.c
            r0.j = r4
            r0.m = r5
            java.lang.Object r8 = r8.emit(r9, r0)
            if (r8 != r1) goto L86
            goto Lc5
        L86:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        L89:
            kotlin.NoWhenBranchMatchedException r8 = new kotlin.NoWhenBranchMatchedException
            r8.<init>()
            throw r8
        L8f:
            kotlinx.coroutines.flow.s0 r9 = r8.f
        L91:
            java.lang.Object r8 = r9.getValue()
            r10 = r8
            com.quizlet.features.emailconfirmation.data.states.a r10 = (com.quizlet.features.emailconfirmation.data.states.a) r10
            com.quizlet.features.emailconfirmation.data.states.a r10 = com.quizlet.features.emailconfirmation.data.states.a.a(r10, r4, r4, r3)
            boolean r8 = r9.k(r8, r10)
            if (r8 == 0) goto L91
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        La5:
            kotlinx.coroutines.flow.d0 r8 = r8.h
            com.quizlet.features.emailconfirmation.data.events.c r9 = com.quizlet.features.emailconfirmation.data.events.c.b
            r0.j = r4
            r0.m = r3
            java.lang.Object r8 = r8.emit(r9, r0)
            if (r8 != r1) goto Lb4
            goto Lc5
        Lb4:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        Lb7:
            kotlinx.coroutines.flow.d0 r8 = r8.h
            com.quizlet.features.emailconfirmation.data.events.c r9 = com.quizlet.features.emailconfirmation.data.events.c.a
            r0.j = r4
            r0.m = r6
            java.lang.Object r8 = r8.emit(r9, r0)
            if (r8 != r1) goto Lc6
        Lc5:
            return r1
        Lc6:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.emailconfirmation.viewmodel.m.A(com.quizlet.features.emailconfirmation.viewmodel.m, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
