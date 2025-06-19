package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import com.google.android.gms.measurement.internal.Z;
import com.quizlet.eventlogger.features.authentication.SignUpWallEventLogger;
import com.quizlet.eventlogger.features.setpage.SetPagePerformanceLogger;
import com.quizlet.generated.enums.A1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.I;

/* loaded from: classes3.dex */
public final class s implements com.quizlet.features.setpage.studymodes.viewmodel.a {
    public final io.ktor.client.plugins.api.d a;
    public final com.quizlet.remote.model.notes.e b;
    public final androidx.work.impl.model.v c;
    public final com.quizlet.features.infra.basestudy.usecase.b d;
    public final androidx.work.impl.model.c e;
    public final com.quizlet.data.interactor.metering.b f;
    public final SignUpWallEventLogger g;
    public final SetPagePerformanceLogger h;
    public final AbstractC5040y i;
    public final com.google.mlkit.vision.documentscanner.internal.c j;
    public I k;
    public final io.reactivex.rxjava3.subjects.r l;

    public s(io.ktor.client.plugins.api.d getStudySetUseCase, com.quizlet.remote.model.notes.e syncStudyModeModelsUseCase, androidx.work.impl.model.v setInSelectedTermsModeUseCase, com.quizlet.features.infra.basestudy.usecase.b getLearnNavigationUseCase, androidx.work.impl.model.c userProperties, com.quizlet.data.interactor.metering.b getMeteringInfoUseCase, SignUpWallEventLogger signUpWallEventLogger, SetPagePerformanceLogger setPagePerformanceLogger, AbstractC5040y ioDispatcher, com.google.mlkit.vision.documentscanner.internal.c gamesUrlBuilder) {
        Intrinsics.checkNotNullParameter(getStudySetUseCase, "getStudySetUseCase");
        Intrinsics.checkNotNullParameter(syncStudyModeModelsUseCase, "syncStudyModeModelsUseCase");
        Intrinsics.checkNotNullParameter(setInSelectedTermsModeUseCase, "setInSelectedTermsModeUseCase");
        Intrinsics.checkNotNullParameter(getLearnNavigationUseCase, "getLearnNavigationUseCase");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(getMeteringInfoUseCase, "getMeteringInfoUseCase");
        Intrinsics.checkNotNullParameter(signUpWallEventLogger, "signUpWallEventLogger");
        Intrinsics.checkNotNullParameter(setPagePerformanceLogger, "setPagePerformanceLogger");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        Intrinsics.checkNotNullParameter(gamesUrlBuilder, "gamesUrlBuilder");
        this.a = getStudySetUseCase;
        this.b = syncStudyModeModelsUseCase;
        this.c = setInSelectedTermsModeUseCase;
        this.d = getLearnNavigationUseCase;
        this.e = userProperties;
        this.f = getMeteringInfoUseCase;
        this.g = signUpWallEventLogger;
        this.h = setPagePerformanceLogger;
        this.i = ioDispatcher;
        this.j = gamesUrlBuilder;
        this.l = Z.f("create(...)");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s r7, com.quizlet.data.model.StudySet r8, boolean r9, java.util.List r10, kotlin.coroutines.jvm.internal.c r11) {
        /*
            r7.getClass()
            boolean r0 = r11 instanceof com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.C4687c
            if (r0 == 0) goto L17
            r0 = r11
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.c r0 = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.C4687c) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L17
            int r1 = r1 - r2
            r0.o = r1
        L15:
            r6 = r0
            goto L1d
        L17:
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.c r0 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.c
            r0.<init>(r7, r11)
            goto L15
        L1d:
            java.lang.Object r11 = r6.m
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.o
            r2 = 1
            if (r1 == 0) goto L3d
            if (r1 != r2) goto L35
            boolean r9 = r6.l
            java.util.List r10 = r6.k
            com.quizlet.data.model.StudySet r8 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
        L31:
            r2 = r8
            r3 = r9
            r4 = r10
            goto L5c
        L35:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L3d:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            r11 = r2
            com.quizlet.features.infra.models.studymodeshared.StudyableModelData$StudySet r2 = new com.quizlet.features.infra.models.studymodeshared.StudyableModelData$StudySet
            long r3 = r8.a
            r2.<init>(r3)
            r6.j = r8
            r6.k = r10
            r6.l = r9
            r6.o = r11
            com.quizlet.features.infra.basestudy.usecase.b r1 = r7.d
            r5 = 0
            long r3 = r8.x
            java.lang.Object r11 = r1.a(r2, r3, r5, r6)
            if (r11 != r0) goto L31
            return r0
        L5c:
            com.quizlet.features.infra.basestudy.usecase.e r11 = (com.quizlet.features.infra.basestudy.usecase.e) r11
            com.quizlet.features.infra.basestudy.data.models.s r1 = new com.quizlet.features.infra.basestudy.data.models.s
            com.quizlet.data.model.w0 r5 = r11.a
            boolean r6 = r11.b
            r1.<init>(r2, r3, r4, r5, r6)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s.a(com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s, com.quizlet.data.model.StudySet, boolean, java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x00be A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s r9, long r10, com.quizlet.generated.enums.P r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            r9.getClass()
            boolean r0 = r13 instanceof com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.C4688d
            if (r0 == 0) goto L17
            r0 = r13
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.d r0 = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.C4688d) r0
            int r1 = r0.p
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L17
            int r1 = r1 - r2
            r0.p = r1
        L15:
            r7 = r0
            goto L1d
        L17:
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.d r0 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.d
            r0.<init>(r9, r13)
            goto L15
        L1d:
            java.lang.Object r13 = r7.n
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.p
            r2 = 3
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L63
            if (r1 == r4) goto L4e
            if (r1 == r3) goto L3a
            if (r1 != r2) goto L32
            androidx.glance.appwidget.protobuf.Z.e(r13)
            return r13
        L32:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L3a:
            long r9 = r7.m
            java.lang.Object r11 = r7.l
            com.quizlet.generated.enums.P r11 = (com.quizlet.generated.enums.P) r11
            java.lang.Object r12 = r7.k
            java.lang.Long r12 = (java.lang.Long) r12
            java.lang.Object r1 = r7.j
            com.quizlet.data.interactor.metering.b r1 = (com.quizlet.data.interactor.metering.b) r1
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r5 = r11
            r4 = r12
            goto La7
        L4e:
            long r10 = r7.m
            java.lang.Object r9 = r7.l
            com.quizlet.data.interactor.metering.b r9 = (com.quizlet.data.interactor.metering.b) r9
            java.lang.Object r12 = r7.k
            com.quizlet.generated.enums.P r12 = (com.quizlet.generated.enums.P) r12
            java.lang.Object r1 = r7.j
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s r1 = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s) r1
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r8 = r1
            r1 = r9
            r9 = r8
            goto L7f
        L63:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            androidx.work.impl.model.c r13 = r9.e
            io.reactivex.rxjava3.internal.operators.single.g r13 = r13.n()
            r7.j = r9
            r7.k = r12
            com.quizlet.data.interactor.metering.b r1 = r9.f
            r7.l = r1
            r7.m = r10
            r7.p = r4
            java.lang.Object r13 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r13, r7)
            if (r13 != r0) goto L7f
            goto Lbd
        L7f:
            java.lang.String r4 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r13, r4)
            java.lang.Number r13 = (java.lang.Number) r13
            long r4 = r13.longValue()
            java.lang.Long r13 = new java.lang.Long
            r13.<init>(r10)
            androidx.work.impl.model.c r9 = r9.e
            r7.j = r1
            r7.k = r13
            r7.l = r12
            r7.m = r4
            r7.p = r3
            java.lang.Object r9 = androidx.camera.core.AbstractC0151c.a(r9, r7)
            if (r9 != r0) goto La2
            goto Lbd
        La2:
            r8 = r13
            r13 = r9
            r9 = r4
            r4 = r8
            r5 = r12
        La7:
            java.lang.Boolean r13 = (java.lang.Boolean) r13
            boolean r6 = r13.booleanValue()
            r11 = 0
            r7.j = r11
            r7.k = r11
            r7.l = r11
            r7.p = r2
            r2 = r9
            java.io.Serializable r9 = r1.a(r2, r4, r5, r6, r7)
            if (r9 != r0) goto Lbe
        Lbd:
            return r0
        Lbe:
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s.b(com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s, long, com.quizlet.generated.enums.P, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object c(com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s r6, long r7, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r6.getClass()
            boolean r0 = r9 instanceof com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.o
            if (r0 == 0) goto L16
            r0 = r9
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.o r0 = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.o) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.o r0 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.o
            r0.<init>(r6, r9)
        L1b:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L3c
            if (r2 == r5) goto L36
            if (r2 != r4) goto L2e
            androidx.glance.appwidget.protobuf.Z.e(r9)
            return r9
        L2e:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L36:
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L5a
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            kotlinx.coroutines.I r9 = r6.k
            if (r9 != 0) goto L5a
            r0.j = r6
            r0.m = r5
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.q r9 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.q
            r9.<init>(r6, r7, r3)
            kotlinx.coroutines.y r7 = r6.i
            java.lang.Object r7 = kotlinx.coroutines.E.J(r7, r9, r0)
            if (r7 != r1) goto L55
            goto L57
        L55:
            kotlin.Unit r7 = kotlin.Unit.a
        L57:
            if (r7 != r1) goto L5a
            goto L69
        L5a:
            kotlinx.coroutines.I r6 = r6.k
            kotlin.jvm.internal.Intrinsics.d(r6)
            r0.j = r3
            r0.m = r4
            java.lang.Object r6 = r6.w(r0)
            if (r6 != r1) goto L6a
        L69:
            return r1
        L6a:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s.c(com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s, long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final Object d(long j, A1 a1, Function2 function2, kotlin.coroutines.jvm.internal.c cVar) {
        return kotlinx.coroutines.E.J(this.i, new C4686b(this, a1, j, function2, null), cVar);
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x0073, code lost:
    
        if (r0 == r1) goto L26;
     */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object e(long r15, kotlin.coroutines.jvm.internal.c r17) throws java.lang.Throwable {
        /*
            r14 = this;
            r0 = r17
            boolean r1 = r0 instanceof com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.C4689e
            if (r1 == 0) goto L16
            r1 = r0
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.e r1 = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.C4689e) r1
            int r2 = r1.n
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L16
            int r2 = r2 - r3
            r1.n = r2
        L14:
            r7 = r1
            goto L1c
        L16:
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.e r1 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.e
            r1.<init>(r14, r0)
            goto L14
        L1c:
            java.lang.Object r0 = r7.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r7.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3e
            if (r2 == r4) goto L36
            if (r2 != r3) goto L2e
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L76
        L2e:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L36:
            long r4 = r7.k
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s r2 = r7.j
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L5c
        L3e:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.quizlet.generated.enums.A1 r12 = com.quizlet.generated.enums.A1.SINGLE_PLAYER_BLAST
            r7.j = r14
            r10 = r15
            r7.k = r10
            r7.n = r4
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.r r8 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.r
            r13 = 0
            r9 = r14
            r8.<init>(r9, r10, r12, r13)
            kotlinx.coroutines.y r0 = r14.i
            java.lang.Object r0 = kotlinx.coroutines.E.J(r0, r8, r7)
            if (r0 != r1) goto L5a
            goto L75
        L5a:
            r2 = r14
            r4 = r15
        L5c:
            com.quizlet.features.infra.basestudy.data.models.o r0 = (com.quizlet.features.infra.basestudy.data.models.o) r0
            if (r0 == 0) goto L61
            return r0
        L61:
            com.quizlet.generated.enums.A1 r0 = com.quizlet.generated.enums.A1.SINGLE_PLAYER_BLAST
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.f r6 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.f
            r8 = 0
            r6.<init>(r2, r4, r8)
            r7.j = r8
            r7.n = r3
            r3 = r4
            r5 = r0
            java.lang.Object r0 = r2.d(r3, r5, r6, r7)
            if (r0 != r1) goto L76
        L75:
            return r1
        L76:
            com.quizlet.features.infra.basestudy.data.models.j r0 = (com.quizlet.features.infra.basestudy.data.models.j) r0
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s.e(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x0073, code lost:
    
        if (r0 == r1) goto L26;
     */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object f(long r15, kotlin.coroutines.jvm.internal.c r17) throws java.lang.Throwable {
        /*
            r14 = this;
            r0 = r17
            boolean r1 = r0 instanceof com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.C4691g
            if (r1 == 0) goto L16
            r1 = r0
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.g r1 = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.C4691g) r1
            int r2 = r1.n
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L16
            int r2 = r2 - r3
            r1.n = r2
        L14:
            r7 = r1
            goto L1c
        L16:
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.g r1 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.g
            r1.<init>(r14, r0)
            goto L14
        L1c:
            java.lang.Object r0 = r7.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r7.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3e
            if (r2 == r4) goto L36
            if (r2 != r3) goto L2e
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L76
        L2e:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L36:
            long r4 = r7.k
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s r2 = r7.j
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L5c
        L3e:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.quizlet.generated.enums.A1 r12 = com.quizlet.generated.enums.A1.BLOCKS
            r7.j = r14
            r10 = r15
            r7.k = r10
            r7.n = r4
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.r r8 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.r
            r13 = 0
            r9 = r14
            r8.<init>(r9, r10, r12, r13)
            kotlinx.coroutines.y r0 = r14.i
            java.lang.Object r0 = kotlinx.coroutines.E.J(r0, r8, r7)
            if (r0 != r1) goto L5a
            goto L75
        L5a:
            r2 = r14
            r4 = r15
        L5c:
            com.quizlet.features.infra.basestudy.data.models.o r0 = (com.quizlet.features.infra.basestudy.data.models.o) r0
            if (r0 == 0) goto L61
            return r0
        L61:
            com.quizlet.generated.enums.A1 r0 = com.quizlet.generated.enums.A1.BLOCKS
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.h r6 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.h
            r8 = 0
            r6.<init>(r2, r4, r8)
            r7.j = r8
            r7.n = r3
            r3 = r4
            r5 = r0
            java.lang.Object r0 = r2.d(r3, r5, r6, r7)
            if (r0 != r1) goto L76
        L75:
            return r1
        L76:
            com.quizlet.features.infra.basestudy.data.models.j r0 = (com.quizlet.features.infra.basestudy.data.models.j) r0
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s.f(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x0086, code lost:
    
        if (r0 == r9) goto L26;
     */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0018  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object g(long r17, java.util.List r19, kotlin.coroutines.jvm.internal.c r20) throws java.lang.Throwable {
        /*
            r16 = this;
            r1 = r16
            r0 = r20
            boolean r2 = r0 instanceof com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.j
            if (r2 == 0) goto L18
            r2 = r0
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.j r2 = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.j) r2
            int r3 = r2.o
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L18
            int r3 = r3 - r4
            r2.o = r3
        L16:
            r8 = r2
            goto L1e
        L18:
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.j r2 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.j
            r2.<init>(r1, r0)
            goto L16
        L1e:
            java.lang.Object r0 = r8.m
            kotlin.coroutines.intrinsics.a r9 = kotlin.coroutines.intrinsics.a.a
            int r2 = r8.o
            r6 = 2
            r3 = 1
            if (r2 == 0) goto L45
            if (r2 == r3) goto L38
            if (r2 != r6) goto L30
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L89
        L30:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r2)
            throw r0
        L38:
            long r2 = r8.l
            java.util.List r4 = r8.k
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s r5 = r8.j
            androidx.glance.appwidget.protobuf.Z.e(r0)
            r12 = r2
            r14 = r4
            r11 = r5
            goto L6a
        L45:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.quizlet.generated.enums.A1 r4 = com.quizlet.generated.enums.A1.LEARNING_ASSISTANT
            r8.j = r1
            r7 = r19
            r8.k = r7
            r10 = r17
            r8.l = r10
            r8.o = r3
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.r r0 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.r
            r5 = 0
            r2 = r10
            r0.<init>(r1, r2, r4, r5)
            kotlinx.coroutines.y r2 = r1.i
            java.lang.Object r0 = kotlinx.coroutines.E.J(r2, r0, r8)
            if (r0 != r9) goto L66
            goto L88
        L66:
            r12 = r17
            r11 = r1
            r14 = r7
        L6a:
            com.quizlet.features.infra.basestudy.data.models.o r0 = (com.quizlet.features.infra.basestudy.data.models.o) r0
            if (r0 == 0) goto L6f
            return r0
        L6f:
            com.quizlet.generated.enums.A1 r0 = com.quizlet.generated.enums.A1.LEARNING_ASSISTANT
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.k r7 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.k
            r15 = 0
            r10 = r7
            r10.<init>(r11, r12, r14, r15)
            r2 = 0
            r8.j = r2
            r8.k = r2
            r8.o = r6
            r6 = r0
            r3 = r11
            r4 = r12
            java.lang.Object r0 = r3.d(r4, r6, r7, r8)
            if (r0 != r9) goto L89
        L88:
            return r9
        L89:
            com.quizlet.features.infra.basestudy.data.models.k r0 = (com.quizlet.features.infra.basestudy.data.models.k) r0
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s.g(long, java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x0073, code lost:
    
        if (r0 == r1) goto L26;
     */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object h(long r15, kotlin.coroutines.jvm.internal.c r17) throws java.lang.Throwable {
        /*
            r14 = this;
            r0 = r17
            boolean r1 = r0 instanceof com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.m
            if (r1 == 0) goto L16
            r1 = r0
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.m r1 = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.m) r1
            int r2 = r1.n
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L16
            int r2 = r2 - r3
            r1.n = r2
        L14:
            r7 = r1
            goto L1c
        L16:
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.m r1 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.m
            r1.<init>(r14, r0)
            goto L14
        L1c:
            java.lang.Object r0 = r7.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r7.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3e
            if (r2 == r4) goto L36
            if (r2 != r3) goto L2e
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L76
        L2e:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L36:
            long r4 = r7.k
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s r2 = r7.j
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L5c
        L3e:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.quizlet.generated.enums.A1 r12 = com.quizlet.generated.enums.A1.TEST
            r7.j = r14
            r10 = r15
            r7.k = r10
            r7.n = r4
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.r r8 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.r
            r13 = 0
            r9 = r14
            r8.<init>(r9, r10, r12, r13)
            kotlinx.coroutines.y r0 = r14.i
            java.lang.Object r0 = kotlinx.coroutines.E.J(r0, r8, r7)
            if (r0 != r1) goto L5a
            goto L75
        L5a:
            r2 = r14
            r4 = r15
        L5c:
            com.quizlet.features.infra.basestudy.data.models.o r0 = (com.quizlet.features.infra.basestudy.data.models.o) r0
            if (r0 == 0) goto L61
            return r0
        L61:
            com.quizlet.generated.enums.A1 r0 = com.quizlet.generated.enums.A1.TEST
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.n r6 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.n
            r8 = 0
            r6.<init>(r2, r4, r8)
            r7.j = r8
            r7.n = r3
            r3 = r4
            r5 = r0
            java.lang.Object r0 = r2.d(r3, r5, r6, r7)
            if (r0 != r1) goto L76
        L75:
            return r1
        L76:
            com.quizlet.features.infra.basestudy.data.models.l r0 = (com.quizlet.features.infra.basestudy.data.models.l) r0
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s.h(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
