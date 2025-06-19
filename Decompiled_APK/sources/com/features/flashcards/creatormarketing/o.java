package com.features.flashcards.creatormarketing;

import com.quizlet.local.datastore.preferences.C4574j;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class o {
    public final C4574j a;
    public final long b;
    public final com.quizlet.data.repository.user.a c;
    public final com.quizlet.data.repository.explanations.question.a d;
    public final com.quizlet.data.repository.explanations.question.a e;

    public o(C4574j dataStore, long j, com.quizlet.data.repository.user.a feature, com.quizlet.data.repository.explanations.question.a sessionThreshold, com.quizlet.data.repository.explanations.question.a frequencyIntervalInDays) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        Intrinsics.checkNotNullParameter(feature, "feature");
        Intrinsics.checkNotNullParameter(sessionThreshold, "sessionThreshold");
        Intrinsics.checkNotNullParameter(frequencyIntervalInDays, "frequencyIntervalInDays");
        this.a = dataStore;
        this.b = j;
        this.c = feature;
        this.d = sessionThreshold;
        this.e = frequencyIntervalInDays;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.jvm.internal.c r11) {
        /*
            r10 = this;
            boolean r0 = r11 instanceof com.features.flashcards.creatormarketing.k
            if (r0 == 0) goto L13
            r0 = r11
            com.features.flashcards.creatormarketing.k r0 = (com.features.flashcards.creatormarketing.k) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.features.flashcards.creatormarketing.k r0 = new com.features.flashcards.creatormarketing.k
            r0.<init>(r10, r11)
        L18:
            java.lang.Object r11 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3c
            if (r2 == r4) goto L34
            if (r2 != r3) goto L2c
            java.lang.Object r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            return r0
        L2c:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r0)
            throw r11
        L34:
            java.lang.Object r2 = r0.j
            com.features.flashcards.creatormarketing.o r2 = (com.features.flashcards.creatormarketing.o) r2
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L4b
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            r0.j = r10
            r0.m = r4
            java.lang.Object r11 = r10.d(r0)
            if (r11 != r1) goto L4a
            goto L9d
        L4a:
            r2 = r10
        L4b:
            r5 = r11
            java.lang.Boolean r5 = (java.lang.Boolean) r5
            boolean r5 = r5.booleanValue()
            if (r5 == 0) goto L9e
            r0.j = r11
            r0.m = r3
            r2.getClass()
            long r5 = java.lang.System.currentTimeMillis()
            com.quizlet.local.datastore.preferences.j r3 = r2.a
            java.lang.Long r7 = new java.lang.Long
            long r8 = r2.b
            r7.<init>(r8)
            java.lang.Object[] r2 = new java.lang.Object[]{r7}
            java.lang.Object[] r2 = java.util.Arrays.copyOf(r2, r4)
            java.lang.String r4 = "creator_marketing_last_shown_timestamp_%s"
            java.lang.String r2 = java.lang.String.format(r4, r2)
            java.lang.String r4 = "format(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r4)
            java.lang.String r4 = "name"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r4)
            androidx.datastore.preferences.core.f r4 = new androidx.datastore.preferences.core.f
            r4.<init>(r2)
            com.quizlet.local.datastore.preferences.i r2 = new com.quizlet.local.datastore.preferences.i
            r7 = 0
            r2.<init>(r4, r5, r7)
            androidx.datastore.core.h r3 = r3.a
            java.lang.Object r0 = com.google.android.gms.internal.mlkit_vision_barcode.S6.d(r3, r2, r0)
            if (r0 != r1) goto L94
            goto L96
        L94:
            kotlin.Unit r0 = kotlin.Unit.a
        L96:
            if (r0 != r1) goto L99
            goto L9b
        L99:
            kotlin.Unit r0 = kotlin.Unit.a
        L9b:
            if (r0 != r1) goto L9e
        L9d:
            return r1
        L9e:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.features.flashcards.creatormarketing.o.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0079  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(kotlin.coroutines.jvm.internal.c r8) {
        /*
            r7 = this;
            boolean r0 = r8 instanceof com.features.flashcards.creatormarketing.l
            if (r0 == 0) goto L13
            r0 = r8
            com.features.flashcards.creatormarketing.l r0 = (com.features.flashcards.creatormarketing.l) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.features.flashcards.creatormarketing.l r0 = new com.features.flashcards.creatormarketing.l
            r0.<init>(r7, r8)
        L18:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3c
            if (r2 == r4) goto L36
            if (r2 != r3) goto L2e
            java.lang.Long r1 = r0.k
            com.features.flashcards.creatormarketing.o r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L6c
        L2e:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L36:
            com.features.flashcards.creatormarketing.o r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L4f
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r7
            r0.n = r4
            com.quizlet.local.datastore.preferences.j r8 = r7.a
            long r5 = r7.b
            java.lang.Object r8 = r8.a(r5, r0)
            if (r8 != r1) goto L4e
            goto L68
        L4e:
            r2 = r7
        L4f:
            java.lang.Long r8 = (java.lang.Long) r8
            if (r8 != 0) goto L56
            java.lang.Boolean r8 = java.lang.Boolean.TRUE
            return r8
        L56:
            com.quizlet.data.repository.explanations.question.a r5 = r2.e
            r0.j = r2
            r0.k = r8
            r0.n = r3
            java.lang.Object r0 = r5.c
            java.lang.Integer r0 = (java.lang.Integer) r0
            java.lang.Object r0 = r5.d(r0)
            if (r0 != r1) goto L69
        L68:
            return r1
        L69:
            r1 = r8
            r8 = r0
            r0 = r2
        L6c:
            java.lang.Number r8 = (java.lang.Number) r8
            int r8 = r8.intValue()
            long r2 = (long) r8
            r5 = 0
            int r8 = (r2 > r5 ? 1 : (r2 == r5 ? 0 : -1))
            if (r8 > 0) goto L7c
            java.lang.Boolean r8 = java.lang.Boolean.FALSE
            return r8
        L7c:
            r0.getClass()
            long r5 = java.lang.System.currentTimeMillis()
            long r0 = r1.longValue()
            long r5 = r5 - r0
            java.util.concurrent.TimeUnit r8 = java.util.concurrent.TimeUnit.DAYS
            long r0 = r8.toMillis(r2)
            int r8 = (r0 > r5 ? 1 : (r0 == r5 ? 0 : -1))
            if (r8 > 0) goto L93
            goto L94
        L93:
            r4 = 0
        L94:
            java.lang.Boolean r8 = java.lang.Boolean.valueOf(r4)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.features.flashcards.creatormarketing.o.b(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x00b7, code lost:
    
        if (r11 == r1) goto L37;
     */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0082  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(kotlin.coroutines.jvm.internal.c r11) {
        /*
            r10 = this;
            boolean r0 = r11 instanceof com.features.flashcards.creatormarketing.m
            if (r0 == 0) goto L13
            r0 = r11
            com.features.flashcards.creatormarketing.m r0 = (com.features.flashcards.creatormarketing.m) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.features.flashcards.creatormarketing.m r0 = new com.features.flashcards.creatormarketing.m
            r0.<init>(r10, r11)
        L18:
            java.lang.Object r11 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 3
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L44
            if (r2 == r5) goto L3e
            if (r2 == r4) goto L36
            if (r2 != r3) goto L2e
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto Lba
        L2e:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r0)
            throw r11
        L36:
            int r2 = r0.k
            com.features.flashcards.creatormarketing.o r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L79
        L3e:
            com.features.flashcards.creatormarketing.o r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L59
        L44:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            r0.j = r10
            r0.n = r5
            com.quizlet.data.repository.explanations.question.a r11 = r10.d
            java.lang.Object r2 = r11.c
            java.lang.Integer r2 = (java.lang.Integer) r2
            java.lang.Object r11 = r11.d(r2)
            if (r11 != r1) goto L58
            goto Lb9
        L58:
            r2 = r10
        L59:
            java.lang.Number r11 = (java.lang.Number) r11
            int r11 = r11.intValue()
            if (r11 > 0) goto L64
            java.lang.Boolean r11 = java.lang.Boolean.FALSE
            return r11
        L64:
            com.quizlet.local.datastore.preferences.j r6 = r2.a
            r0.j = r2
            r0.k = r11
            r0.n = r4
            long r7 = r2.b
            java.lang.Object r4 = r6.b(r7, r0)
            if (r4 != r1) goto L75
            goto Lb9
        L75:
            r9 = r2
            r2 = r11
            r11 = r4
            r4 = r9
        L79:
            java.lang.Number r11 = (java.lang.Number) r11
            int r11 = r11.intValue()
            int r11 = r11 + r5
            if (r11 >= r2) goto Lbb
            com.quizlet.local.datastore.preferences.j r11 = r4.a
            r2 = 0
            r0.j = r2
            r0.n = r3
            java.lang.Long r3 = new java.lang.Long
            long r6 = r4.b
            r3.<init>(r6)
            java.lang.Object[] r3 = new java.lang.Object[]{r3}
            java.lang.Object[] r3 = java.util.Arrays.copyOf(r3, r5)
            java.lang.String r4 = "creator_marketing_user_session_count_%s"
            java.lang.String r3 = java.lang.String.format(r4, r3)
            java.lang.String r4 = "format(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r4)
            androidx.datastore.preferences.core.f r3 = com.google.android.gms.internal.mlkit_vision_barcode.R6.c(r3)
            com.quizlet.local.datastore.preferences.h r4 = new com.quizlet.local.datastore.preferences.h
            r4.<init>(r3, r2)
            androidx.datastore.core.h r11 = r11.a
            java.lang.Object r11 = com.google.android.gms.internal.mlkit_vision_barcode.S6.d(r11, r4, r0)
            if (r11 != r1) goto Lb5
            goto Lb7
        Lb5:
            kotlin.Unit r11 = kotlin.Unit.a
        Lb7:
            if (r11 != r1) goto Lba
        Lb9:
            return r1
        Lba:
            r5 = 0
        Lbb:
            java.lang.Boolean r11 = java.lang.Boolean.valueOf(r5)
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.features.flashcards.creatormarketing.o.c(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x006b  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(kotlin.coroutines.jvm.internal.c r7) {
        /*
            r6 = this;
            boolean r0 = r7 instanceof com.features.flashcards.creatormarketing.n
            if (r0 == 0) goto L13
            r0 = r7
            com.features.flashcards.creatormarketing.n r0 = (com.features.flashcards.creatormarketing.n) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.features.flashcards.creatormarketing.n r0 = new com.features.flashcards.creatormarketing.n
            r0.<init>(r6, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 3
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L41
            if (r2 == r5) goto L3b
            if (r2 == r4) goto L35
            if (r2 != r3) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r7)
            return r7
        L2d:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L35:
            com.features.flashcards.creatormarketing.o r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L63
        L3b:
            com.features.flashcards.creatormarketing.o r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L50
        L41:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r6
            r0.m = r5
            java.lang.Object r7 = r6.c(r0)
            if (r7 != r1) goto L4f
            goto L78
        L4f:
            r2 = r6
        L50:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 == 0) goto L7a
            r0.j = r2
            r0.m = r4
            java.lang.Object r7 = r2.b(r0)
            if (r7 != r1) goto L63
            goto L78
        L63:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 == 0) goto L7a
            com.quizlet.data.repository.user.a r7 = r2.c
            r2 = 0
            r0.j = r2
            r0.m = r3
            java.lang.Object r7 = r7.j(r0)
            if (r7 != r1) goto L79
        L78:
            return r1
        L79:
            return r7
        L7a:
            java.lang.Boolean r7 = java.lang.Boolean.FALSE
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.features.flashcards.creatormarketing.o.d(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
