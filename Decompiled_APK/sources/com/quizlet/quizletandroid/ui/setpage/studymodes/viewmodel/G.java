package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes3.dex */
public final class G {
    public final com.quizlet.data.interactor.set.c a;
    public final StudyModeMeteringEventLogger b;
    public final y c;
    public final AbstractC5040y d;
    public final com.quizlet.data.repository.folderset.c e;
    public final com.quizlet.data.repository.folderset.c f;
    public final com.quizlet.shared.usecase.folderstudymaterials.a g;
    public final com.quizlet.data.repository.set.f h;
    public final LinkedHashMap i;

    public G(com.quizlet.data.interactor.set.c getTermsWithStarredUseCase, StudyModeMeteringEventLogger meteringLogger, y setPageStudyModeMeteringManager, AbstractC5040y ioDispatcher, com.quizlet.data.repository.folderset.c blocksFeature, com.quizlet.data.repository.folderset.c blastFeature, com.quizlet.shared.usecase.folderstudymaterials.a gamesSetEligibilityChecker, com.quizlet.data.repository.set.f alternateStudyModeNamesType) {
        Intrinsics.checkNotNullParameter(getTermsWithStarredUseCase, "getTermsWithStarredUseCase");
        Intrinsics.checkNotNullParameter(meteringLogger, "meteringLogger");
        Intrinsics.checkNotNullParameter(setPageStudyModeMeteringManager, "setPageStudyModeMeteringManager");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        Intrinsics.checkNotNullParameter(blocksFeature, "blocksFeature");
        Intrinsics.checkNotNullParameter(blastFeature, "blastFeature");
        Intrinsics.checkNotNullParameter(gamesSetEligibilityChecker, "gamesSetEligibilityChecker");
        Intrinsics.checkNotNullParameter(alternateStudyModeNamesType, "alternateStudyModeNamesType");
        this.a = getTermsWithStarredUseCase;
        this.b = meteringLogger;
        this.c = setPageStudyModeMeteringManager;
        this.d = ioDispatcher;
        this.e = blocksFeature;
        this.f = blastFeature;
        this.g = gamesSetEligibilityChecker;
        this.h = alternateStudyModeNamesType;
        this.i = new LinkedHashMap();
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x00d6  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00ec  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0108  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G r9, long r10, boolean r12, boolean r13, kotlin.coroutines.jvm.internal.c r14) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 279
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G.a(com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G, long, boolean, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(boolean r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.A
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.A r0 = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.A) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.A r0 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.A
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            boolean r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L41
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            r0.m = r3
            com.quizlet.data.repository.folderset.c r6 = r4.f
            java.lang.Object r6 = r6.m(r0)
            if (r6 != r1) goto L41
            return r1
        L41:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 == 0) goto L51
            if (r5 == 0) goto L4e
            com.quizlet.data.model.o0 r5 = com.quizlet.data.model.C4153o0.a
            return r5
        L4e:
            com.quizlet.data.model.m0 r5 = com.quizlet.data.model.C4147m0.a
            return r5
        L51:
            com.quizlet.data.model.n0 r5 = com.quizlet.data.model.C4150n0.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G.b(boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(boolean r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.B
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.B r0 = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.B) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.B r0 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.B
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            boolean r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L41
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            r0.m = r3
            com.quizlet.data.repository.folderset.c r6 = r4.e
            java.lang.Object r6 = r6.m(r0)
            if (r6 != r1) goto L41
            return r1
        L41:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 == 0) goto L51
            if (r5 == 0) goto L4e
            com.quizlet.data.model.o0 r5 = com.quizlet.data.model.C4153o0.a
            return r5
        L4e:
            com.quizlet.data.model.m0 r5 = com.quizlet.data.model.C4147m0.a
            return r5
        L51:
            com.quizlet.data.model.n0 r5 = com.quizlet.data.model.C4150n0.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G.c(boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Enum d(long r9, com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.z r11, kotlin.coroutines.jvm.internal.c r12) throws java.lang.Throwable {
        /*
            r8 = this;
            boolean r0 = r12 instanceof com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.C
            if (r0 == 0) goto L13
            r0 = r12
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.C r0 = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.C) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.C r0 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.C
            r0.<init>(r8, r12)
        L18:
            java.lang.Object r12 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            long r9 = r0.k
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G r11 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
        L2a:
            r3 = r9
            goto L72
        L2c:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            r0.j = r8
            r0.k = r9
            r0.n = r3
            int r11 = r11.ordinal()
            r12 = 0
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.y r2 = r8.c
            if (r11 == 0) goto L5e
            if (r11 != r3) goto L58
            r2.getClass()
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.x r11 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.x
            r11.<init>(r2, r9, r12)
            kotlinx.coroutines.y r12 = r2.e
            java.lang.Object r11 = kotlinx.coroutines.E.J(r12, r11, r0)
        L56:
            r12 = r11
            goto L6d
        L58:
            kotlin.NoWhenBranchMatchedException r9 = new kotlin.NoWhenBranchMatchedException
            r9.<init>()
            throw r9
        L5e:
            r2.getClass()
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.u r11 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.u
            r11.<init>(r2, r9, r12)
            kotlinx.coroutines.y r12 = r2.e
            java.lang.Object r11 = kotlinx.coroutines.E.J(r12, r11, r0)
            goto L56
        L6d:
            if (r12 != r1) goto L70
            return r1
        L70:
            r11 = r8
            goto L2a
        L72:
            com.quizlet.data.model.w0 r12 = (com.quizlet.data.model.InterfaceC4176w0) r12
            boolean r9 = r12.a0()
            if (r9 == 0) goto La7
            java.util.LinkedHashMap r9 = r11.i
            com.quizlet.generated.enums.P r10 = r12.c0()
            java.lang.Object r10 = r9.get(r10)
            java.lang.Boolean r0 = java.lang.Boolean.TRUE
            boolean r10 = kotlin.jvm.internal.Intrinsics.b(r10, r0)
            if (r10 != 0) goto La4
            com.quizlet.studiablemodels.StudiableMeteringData r5 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3097a5.d(r12)
            com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger r2 = r11.b
            java.lang.String r10 = "meteringData"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r10)
            r6 = 0
            java.lang.String r7 = "set_page_paywall_lock_impression"
            r2.b(r3, r5, r6, r7)
            com.quizlet.generated.enums.P r10 = r12.c0()
            r9.put(r10, r0)
        La4:
            com.quizlet.data.model.A0 r9 = com.quizlet.data.model.A0.a
            return r9
        La7:
            com.quizlet.data.model.A0 r9 = com.quizlet.data.model.A0.b
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G.d(long, com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.z, kotlin.coroutines.jvm.internal.c):java.lang.Enum");
    }
}
