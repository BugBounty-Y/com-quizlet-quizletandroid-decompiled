package com.quizlet.quizletandroid.interactor;

import androidx.work.impl.model.v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p {
    public final com.google.firebase.crashlytics.internal.common.j a;
    public final com.google.firebase.crashlytics.internal.settings.b b;
    public final v c;

    public p(com.google.firebase.crashlytics.internal.common.j libraryPreferencesDataStore, com.google.firebase.crashlytics.internal.settings.b checkNotesEligibilityUseCase, v getPracticeTestsLibraryTabEligibilityUseCase) {
        Intrinsics.checkNotNullParameter(libraryPreferencesDataStore, "libraryPreferencesDataStore");
        Intrinsics.checkNotNullParameter(checkNotesEligibilityUseCase, "checkNotesEligibilityUseCase");
        Intrinsics.checkNotNullParameter(getPracticeTestsLibraryTabEligibilityUseCase, "getPracticeTestsLibraryTabEligibilityUseCase");
        this.a = libraryPreferencesDataStore;
        this.b = checkNotesEligibilityUseCase;
        this.c = getPracticeTestsLibraryTabEligibilityUseCase;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Enum a(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.quizletandroid.interactor.n
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.quizletandroid.interactor.n r0 = (com.quizlet.quizletandroid.interactor.n) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.interactor.n r0 = new com.quizlet.quizletandroid.interactor.n
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L51
        L27:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.l = r3
            com.google.firebase.crashlytics.internal.common.j r6 = r5.a
            java.lang.String r2 = "lastLibraryTabVisitedKey"
            androidx.datastore.preferences.core.f r2 = com.google.android.gms.internal.mlkit_vision_barcode.R6.c(r2)
            java.lang.Object r6 = r6.b
            androidx.datastore.core.h r6 = (androidx.datastore.core.InterfaceC1076h) r6
            kotlinx.coroutines.flow.i r6 = r6.getData()
            com.quizlet.local.datastore.preferences.x r3 = new com.quizlet.local.datastore.preferences.x
            r4 = 1
            r3.<init>(r6, r2, r4)
            java.lang.Object r6 = kotlinx.coroutines.flow.e0.r(r3, r0)
            if (r6 != r1) goto L51
            return r1
        L51:
            java.lang.Integer r6 = (java.lang.Integer) r6
            if (r6 == 0) goto L62
            kotlin.enums.b r0 = com.quizlet.data.model.EnumC4164s0.h
            int r6 = r6.intValue()
            java.lang.Object r6 = r0.get(r6)
            com.quizlet.data.model.s0 r6 = (com.quizlet.data.model.EnumC4164s0) r6
            return r6
        L62:
            com.quizlet.data.model.s0 r6 = com.quizlet.quizletandroid.interactor.q.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.interactor.p.a(kotlin.coroutines.jvm.internal.c):java.lang.Enum");
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x007f A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0098  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x009b A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Enum b(kotlin.coroutines.jvm.internal.c r9) {
        /*
            r8 = this;
            boolean r0 = r9 instanceof com.quizlet.quizletandroid.interactor.o
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.quizletandroid.interactor.o r0 = (com.quizlet.quizletandroid.interactor.o) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.interactor.o r0 = new com.quizlet.quizletandroid.interactor.o
            r0.<init>(r8, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 3
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L49
            if (r2 == r5) goto L41
            if (r2 == r4) goto L39
            if (r2 != r3) goto L31
            java.lang.Object r0 = r0.j
            com.quizlet.data.model.s0 r0 = (com.quizlet.data.model.EnumC4164s0) r0
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L74
        L31:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L39:
            java.lang.Object r0 = r0.j
            com.quizlet.data.model.s0 r0 = (com.quizlet.data.model.EnumC4164s0) r0
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L90
        L41:
            java.lang.Object r2 = r0.j
            com.quizlet.quizletandroid.interactor.p r2 = (com.quizlet.quizletandroid.interactor.p) r2
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L58
        L49:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r8
            r0.m = r5
            java.lang.Enum r9 = r8.a(r0)
            if (r9 != r1) goto L57
            goto L8c
        L57:
            r2 = r8
        L58:
            com.quizlet.data.model.s0 r9 = (com.quizlet.data.model.EnumC4164s0) r9
            int r6 = r9.ordinal()
            if (r6 == r5) goto L80
            r4 = 4
            if (r6 == r4) goto L64
            return r9
        L64:
            androidx.work.impl.model.v r2 = r2.c
            r0.j = r9
            r0.m = r3
            java.lang.Object r0 = r2.i(r0)
            if (r0 != r1) goto L71
            goto L8c
        L71:
            r7 = r0
            r0 = r9
            r9 = r7
        L74:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            if (r9 != 0) goto L7f
            com.quizlet.data.model.s0 r9 = com.quizlet.quizletandroid.interactor.q.a
            return r9
        L7f:
            return r0
        L80:
            com.google.firebase.crashlytics.internal.settings.b r2 = r2.b
            r0.j = r9
            r0.m = r4
            java.lang.Object r0 = r2.h(r0)
            if (r0 != r1) goto L8d
        L8c:
            return r1
        L8d:
            r7 = r0
            r0 = r9
            r9 = r7
        L90:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            if (r9 != 0) goto L9b
            com.quizlet.data.model.s0 r9 = com.quizlet.quizletandroid.interactor.q.a
            return r9
        L9b:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.interactor.p.b(kotlin.coroutines.jvm.internal.c):java.lang.Enum");
    }
}
