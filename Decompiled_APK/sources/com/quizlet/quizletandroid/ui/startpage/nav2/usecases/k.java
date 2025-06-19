package com.quizlet.quizletandroid.ui.startpage.nav2.usecases;

import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes3.dex */
public final class k {
    public final androidx.work.impl.model.c a;
    public final com.lyft.android.scissors.b b;
    public final com.quizlet.data.repository.user.a c;
    public final u d;

    public k(androidx.work.impl.model.c userProps, com.lyft.android.scissors.b onboardingELLPreferencesStoreManager, com.quizlet.data.repository.user.a onboardingELLHomeSectionFeature) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        Intrinsics.checkNotNullParameter(onboardingELLPreferencesStoreManager, "onboardingELLPreferencesStoreManager");
        Intrinsics.checkNotNullParameter(onboardingELLHomeSectionFeature, "onboardingELLHomeSectionFeature");
        this.a = userProps;
        this.b = onboardingELLPreferencesStoreManager;
        this.c = onboardingELLHomeSectionFeature;
        this.d = l.b(new com.quizlet.login.magiclink.ui.e(this, 27));
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0056, code lost:
    
        if (r6 == r1) goto L24;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable a(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.quizletandroid.ui.startpage.nav2.usecases.c
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.c r0 = (com.quizlet.quizletandroid.ui.startpage.nav2.usecases.c) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.c r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.c
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L59
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L32:
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L49
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            r0.m = r4
            androidx.work.impl.model.c r6 = r5.a
            java.lang.Enum r6 = r6.d(r0)
            if (r6 != r1) goto L48
            goto L58
        L48:
            r2 = r5
        L49:
            com.quizlet.generated.enums.H r6 = (com.quizlet.generated.enums.H) r6
            if (r6 == 0) goto L85
            r4 = 0
            r0.j = r4
            r0.m = r3
            java.lang.Object r6 = r2.f(r6, r0)
            if (r6 != r1) goto L59
        L58:
            return r1
        L59:
            java.lang.Iterable r6 = (java.lang.Iterable) r6
            java.util.ArrayList r0 = new java.util.ArrayList
            r1 = 10
            int r1 = kotlin.collections.C.q(r6, r1)
            r0.<init>(r1)
            java.util.Iterator r6 = r6.iterator()
        L6a:
            boolean r1 = r6.hasNext()
            if (r1 == 0) goto L84
            java.lang.Object r1 = r6.next()
            com.quizlet.quizletandroid.ui.startpage.nav2.model.L r1 = (com.quizlet.quizletandroid.ui.startpage.nav2.model.L) r1
            com.quizlet.quizletandroid.ui.startpage.nav2.model.M r2 = new com.quizlet.quizletandroid.ui.startpage.nav2.model.M
            com.quizlet.generated.enums.S0 r3 = r1.a
            r4 = 4
            java.lang.Integer r1 = r1.b
            r2.<init>(r3, r1, r4)
            r0.add(r2)
            goto L6a
        L84:
            return r0
        L85:
            kotlin.collections.K r6 = kotlin.collections.K.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k.a(kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x0061, code lost:
    
        if (r8 == r1) goto L22;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable b(kotlin.coroutines.jvm.internal.c r8) {
        /*
            r7 = this;
            boolean r0 = r8 instanceof com.quizlet.quizletandroid.ui.startpage.nav2.usecases.d
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.d r0 = (com.quizlet.quizletandroid.ui.startpage.nav2.usecases.d) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.d r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.d
            r0.<init>(r7, r8)
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
            goto L64
        L2b:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L33:
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L4e
        L39:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            androidx.work.impl.model.c r8 = r7.a
            io.reactivex.rxjava3.internal.operators.single.g r8 = r8.n()
            r0.j = r7
            r0.m = r5
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r8, r0)
            if (r8 != r1) goto L4d
            goto L63
        L4d:
            r2 = r7
        L4e:
            java.lang.String r5 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r5)
            java.lang.Number r8 = (java.lang.Number) r8
            long r5 = r8.longValue()
            r0.j = r3
            r0.m = r4
            java.lang.Object r8 = r2.g(r5, r0)
            if (r8 != r1) goto L64
        L63:
            return r1
        L64:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            if (r8 == 0) goto L9f
            com.quizlet.generated.enums.S0 r8 = com.quizlet.generated.enums.S0.IELTS
            com.quizlet.generated.enums.S0 r0 = com.quizlet.generated.enums.S0.TOEFL
            com.quizlet.generated.enums.S0 r1 = com.quizlet.generated.enums.S0.TOEIC
            com.quizlet.generated.enums.S0[] r8 = new com.quizlet.generated.enums.S0[]{r8, r0, r1}
            java.util.List r8 = kotlin.collections.B.j(r8)
            java.util.ArrayList r0 = new java.util.ArrayList
            r1 = 10
            int r1 = kotlin.collections.C.q(r8, r1)
            r0.<init>(r1)
            java.util.Iterator r8 = r8.iterator()
        L89:
            boolean r1 = r8.hasNext()
            if (r1 == 0) goto L9e
            java.lang.Object r1 = r8.next()
            com.quizlet.generated.enums.S0 r1 = (com.quizlet.generated.enums.S0) r1
            com.quizlet.quizletandroid.ui.startpage.nav2.model.M r2 = new com.quizlet.quizletandroid.ui.startpage.nav2.model.M
            r2.<init>(r1, r3, r4)
            r0.add(r2)
            goto L89
        L9e:
            return r0
        L9f:
            kotlin.collections.K r8 = kotlin.collections.K.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k.b(kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Enum c(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.quizletandroid.ui.startpage.nav2.usecases.e
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.e r0 = (com.quizlet.quizletandroid.ui.startpage.nav2.usecases.e) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.e r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.e
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L3d
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.l = r3
            androidx.work.impl.model.c r5 = r4.a
            java.lang.Enum r5 = r5.d(r0)
            if (r5 != r1) goto L3d
            return r1
        L3d:
            com.quizlet.generated.enums.H r5 = (com.quizlet.generated.enums.H) r5
            if (r5 != 0) goto L43
            r5 = -1
            goto L4b
        L43:
            int[] r0 = com.quizlet.quizletandroid.ui.startpage.nav2.usecases.b.a
            int r5 = r5.ordinal()
            r5 = r0[r5]
        L4b:
            switch(r5) {
                case 1: goto L59;
                case 2: goto L56;
                case 3: goto L56;
                case 4: goto L56;
                case 5: goto L53;
                case 6: goto L50;
                default: goto L4e;
            }
        L4e:
            r5 = 0
            return r5
        L50:
            com.quizlet.generated.enums.S0 r5 = com.quizlet.generated.enums.S0.VIETNAM_ELL
            return r5
        L53:
            com.quizlet.generated.enums.S0 r5 = com.quizlet.generated.enums.S0.MEXICO_ELL
            return r5
        L56:
            com.quizlet.generated.enums.S0 r5 = com.quizlet.generated.enums.S0.FLASHCARDS_ELL
            return r5
        L59:
            com.quizlet.generated.enums.S0 r5 = com.quizlet.generated.enums.S0.BRAZIL_ELL
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k.c(kotlin.coroutines.jvm.internal.c):java.lang.Enum");
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x008b  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable d(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.quizletandroid.ui.startpage.nav2.usecases.f
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.f r0 = (com.quizlet.quizletandroid.ui.startpage.nav2.usecases.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.f r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.f
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L3d
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.l = r3
            com.lyft.android.scissors.b r7 = r4.b
            java.lang.Object r7 = r7.h(r5, r0)
            if (r7 != r1) goto L3d
            return r1
        L3d:
            java.lang.Iterable r7 = (java.lang.Iterable) r7
            java.util.ArrayList r5 = new java.util.ArrayList
            r5.<init>()
            java.util.Iterator r6 = r7.iterator()
        L48:
            boolean r7 = r6.hasNext()
            if (r7 == 0) goto L92
            java.lang.Object r7 = r6.next()
            java.lang.String r7 = (java.lang.String) r7
            int r0 = r7.hashCode()
            r1 = 69548335(0x425392f, float:1.9421914E-36)
            if (r0 == r1) goto L80
            r1 = 79997808(0x4c4ab70, float:4.623682E-36)
            if (r0 == r1) goto L74
            r1 = 79997892(0x4c4abc4, float:4.623712E-36)
            if (r0 == r1) goto L68
            goto L8b
        L68:
            java.lang.String r0 = "TOEIC"
            boolean r7 = r7.equals(r0)
            if (r7 != 0) goto L71
            goto L8b
        L71:
            com.quizlet.generated.enums.S0 r7 = com.quizlet.generated.enums.S0.TOEIC
            goto L8c
        L74:
            java.lang.String r0 = "TOEFL"
            boolean r7 = r7.equals(r0)
            if (r7 != 0) goto L7d
            goto L8b
        L7d:
            com.quizlet.generated.enums.S0 r7 = com.quizlet.generated.enums.S0.TOEFL
            goto L8c
        L80:
            java.lang.String r0 = "IELTS"
            boolean r7 = r7.equals(r0)
            if (r7 == 0) goto L8b
            com.quizlet.generated.enums.S0 r7 = com.quizlet.generated.enums.S0.IELTS
            goto L8c
        L8b:
            r7 = 0
        L8c:
            if (r7 == 0) goto L48
            r5.add(r7)
            goto L48
        L92:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k.d(long, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x00af  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00b9  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00cb  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00e4 A[LOOP:0: B:43:0x00de->B:45:0x00e4, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable e(kotlin.coroutines.jvm.internal.c r12) {
        /*
            Method dump skipped, instructions count: 244
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k.e(kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0104  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x013b  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x0144  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0158 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r14v9, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r2v14, types: [java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object f(com.quizlet.generated.enums.H r14, kotlin.coroutines.jvm.internal.c r15) {
        /*
            Method dump skipped, instructions count: 345
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k.f(com.quizlet.generated.enums.H, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:37:0x00a5, code lost:
    
        if (r10 == r1) goto L38;
     */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0083  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object g(long r8, kotlin.coroutines.jvm.internal.c r10) {
        /*
            r7 = this;
            boolean r0 = r10 instanceof com.quizlet.quizletandroid.ui.startpage.nav2.usecases.i
            if (r0 == 0) goto L13
            r0 = r10
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.i r0 = (com.quizlet.quizletandroid.ui.startpage.nav2.usecases.i) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.i r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.i
            r0.<init>(r7, r10)
        L18:
            java.lang.Object r10 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 4
            r4 = 3
            r5 = 2
            r6 = 1
            if (r2 == 0) goto L51
            if (r2 == r6) goto L49
            if (r2 == r5) goto L41
            if (r2 == r4) goto L39
            if (r2 != r3) goto L31
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto La8
        L31:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L39:
            long r8 = r0.k
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L92
        L41:
            long r8 = r0.k
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L7b
        L49:
            long r8 = r0.k
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L64
        L51:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            r0.j = r7
            r0.k = r8
            r0.n = r6
            com.quizlet.data.repository.user.a r10 = r7.c
            java.lang.Object r10 = r10.j(r0)
            if (r10 != r1) goto L63
            goto La7
        L63:
            r2 = r7
        L64:
            java.lang.Boolean r10 = (java.lang.Boolean) r10
            boolean r10 = r10.booleanValue()
            if (r10 == 0) goto Lb1
            com.lyft.android.scissors.b r10 = r2.b
            r0.j = r2
            r0.k = r8
            r0.n = r5
            java.lang.Object r10 = r10.k(r8, r0)
            if (r10 != r1) goto L7b
            goto La7
        L7b:
            java.lang.Boolean r10 = (java.lang.Boolean) r10
            boolean r10 = r10.booleanValue()
            if (r10 == 0) goto Lb1
            com.lyft.android.scissors.b r10 = r2.b
            r0.j = r2
            r0.k = r8
            r0.n = r4
            java.lang.Object r10 = r10.j(r8, r0)
            if (r10 != r1) goto L92
            goto La7
        L92:
            java.lang.Boolean r10 = (java.lang.Boolean) r10
            boolean r10 = r10.booleanValue()
            if (r10 == 0) goto Lb1
            com.lyft.android.scissors.b r10 = r2.b
            r2 = 0
            r0.j = r2
            r0.n = r3
            java.lang.Object r10 = r10.h(r8, r0)
            if (r10 != r1) goto La8
        La7:
            return r1
        La8:
            java.util.Set r10 = (java.util.Set) r10
            boolean r8 = r10.isEmpty()
            if (r8 == 0) goto Lb1
            goto Lb2
        Lb1:
            r6 = 0
        Lb2:
            java.lang.Boolean r8 = java.lang.Boolean.valueOf(r6)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k.g(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object h(long r6, java.util.List r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r5 = this;
            boolean r0 = r9 instanceof com.quizlet.quizletandroid.ui.startpage.nav2.usecases.j
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.j r0 = (com.quizlet.quizletandroid.ui.startpage.nav2.usecases.j) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.j r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.j
            r0.<init>(r5, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3a
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r9)
            return r9
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            long r6 = r0.k
            com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L53
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            boolean r8 = r8.isEmpty()
            if (r8 == 0) goto L6a
            r0.j = r5
            r0.k = r6
            r0.n = r4
            com.lyft.android.scissors.b r8 = r5.b
            java.lang.Object r9 = r8.k(r6, r0)
            if (r9 != r1) goto L52
            goto L68
        L52:
            r8 = r5
        L53:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            if (r9 == 0) goto L6a
            com.lyft.android.scissors.b r8 = r8.b
            r9 = 0
            r0.j = r9
            r0.n = r3
            java.lang.Object r6 = r8.j(r6, r0)
            if (r6 != r1) goto L69
        L68:
            return r1
        L69:
            return r6
        L6a:
            java.lang.Boolean r6 = java.lang.Boolean.FALSE
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k.h(long, java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
