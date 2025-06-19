package com.quizlet.data.interactor.course;

import android.content.Context;
import android.content.Intent;
import androidx.compose.foundation.lazy.grid.m;
import androidx.work.impl.model.n;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.generated.enums.A1;
import com.quizlet.quizletandroid.util.o;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e implements com.quizlet.infra.androidcontracts.deeplink.a {
    public long a;
    public final Object b;
    public final Object c;

    public e(long j, A1 a1, Double d) {
        this.a = j;
        this.b = a1;
        this.c = d;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intent intentB = com.quizlet.features.setpage.e.b(SetPageActivity.h1, context, this.a, (A1) this.b, (Double) this.c, null, null, false, null, 240);
        intentB.addFlags(268435456);
        Unit unit = Unit.a;
        return new Intent[]{intentB};
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public boolean b() {
        return false;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public Intent[] c(Context context, com.quizlet.quizletandroid.managers.deeplinks.h hVar) {
        return AbstractC3508o4.b(this, context, hVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable d(kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r8 = this;
            boolean r0 = r9 instanceof com.quizlet.data.interactor.practicetests.c
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.data.interactor.practicetests.c r0 = (com.quizlet.data.interactor.practicetests.c) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.practicetests.c r0 = new com.quizlet.data.interactor.practicetests.c
            r0.<init>(r8, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            com.quizlet.data.interactor.course.e r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Exception -> L29
            goto L53
        L29:
            r9 = move-exception
            goto Ld6
        L2c:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.Object r9 = r8.b     // Catch: java.lang.Exception -> L29
            com.google.android.gms.internal.ads.C3 r9 = (com.google.android.gms.internal.ads.C3) r9     // Catch: java.lang.Exception -> L29
            long r4 = r8.a     // Catch: java.lang.Exception -> L29
            r0.j = r8     // Catch: java.lang.Exception -> L29
            r0.m = r3     // Catch: java.lang.Exception -> L29
            com.quizlet.remote.model.practicetests.g r2 = new com.quizlet.remote.model.practicetests.g     // Catch: java.lang.Exception -> L29
            r3 = 0
            r2.<init>(r9, r4, r3)     // Catch: java.lang.Exception -> L29
            java.lang.Object r9 = r9.b     // Catch: java.lang.Exception -> L29
            kotlinx.coroutines.y r9 = (kotlinx.coroutines.AbstractC5040y) r9     // Catch: java.lang.Exception -> L29
            java.lang.Object r9 = kotlinx.coroutines.E.J(r9, r2, r0)     // Catch: java.lang.Exception -> L29
            if (r9 != r1) goto L52
            return r1
        L52:
            r0 = r8
        L53:
            java.util.List r9 = (java.util.List) r9     // Catch: java.lang.Exception -> L29
            java.util.LinkedHashMap r1 = new java.util.LinkedHashMap     // Catch: java.lang.Exception -> L29
            r1.<init>()     // Catch: java.lang.Exception -> L29
            long r2 = java.lang.System.currentTimeMillis()     // Catch: java.lang.Exception -> L29
            com.quizlet.data.interactor.practicetests.b r4 = new com.quizlet.data.interactor.practicetests.b     // Catch: java.lang.Exception -> L29
            r4.<init>(r2)     // Catch: java.lang.Exception -> L29
            java.util.List r9 = kotlin.collections.CollectionsKt.n0(r9, r4)     // Catch: java.lang.Exception -> L29
            java.util.Iterator r9 = r9.iterator()     // Catch: java.lang.Exception -> L29
        L6b:
            boolean r4 = r9.hasNext()     // Catch: java.lang.Exception -> L29
            if (r4 == 0) goto La3
            java.lang.Object r4 = r9.next()     // Catch: java.lang.Exception -> L29
            com.quizlet.data.model.S0 r4 = (com.quizlet.data.model.S0) r4     // Catch: java.lang.Exception -> L29
            java.lang.Object r5 = r0.c     // Catch: java.lang.Exception -> L29
            com.quizlet.quizletandroid.util.o r5 = (com.quizlet.quizletandroid.util.o) r5     // Catch: java.lang.Exception -> L29
            long r6 = r4.g     // Catch: java.lang.Exception -> L29
            long r5 = r5.a(r2, r6)     // Catch: java.lang.Exception -> L29
            java.lang.Object r7 = r0.c     // Catch: java.lang.Exception -> L29
            com.quizlet.quizletandroid.util.o r7 = (com.quizlet.quizletandroid.util.o) r7     // Catch: java.lang.Exception -> L29
            java.lang.String r5 = r7.b(r2, r5)     // Catch: java.lang.Exception -> L29
            boolean r6 = r1.containsKey(r5)     // Catch: java.lang.Exception -> L29
            if (r6 != 0) goto L97
            java.util.ArrayList r6 = new java.util.ArrayList     // Catch: java.lang.Exception -> L29
            r6.<init>()     // Catch: java.lang.Exception -> L29
            r1.put(r5, r6)     // Catch: java.lang.Exception -> L29
        L97:
            java.lang.Object r5 = r1.get(r5)     // Catch: java.lang.Exception -> L29
            java.util.List r5 = (java.util.List) r5     // Catch: java.lang.Exception -> L29
            if (r5 == 0) goto L6b
            r5.add(r4)     // Catch: java.lang.Exception -> L29
            goto L6b
        La3:
            java.util.ArrayList r9 = new java.util.ArrayList     // Catch: java.lang.Exception -> L29
            int r0 = r1.size()     // Catch: java.lang.Exception -> L29
            r9.<init>(r0)     // Catch: java.lang.Exception -> L29
            java.util.Set r0 = r1.entrySet()     // Catch: java.lang.Exception -> L29
            java.util.Iterator r0 = r0.iterator()     // Catch: java.lang.Exception -> L29
        Lb4:
            boolean r1 = r0.hasNext()     // Catch: java.lang.Exception -> L29
            if (r1 == 0) goto Ld5
            java.lang.Object r1 = r0.next()     // Catch: java.lang.Exception -> L29
            java.util.Map$Entry r1 = (java.util.Map.Entry) r1     // Catch: java.lang.Exception -> L29
            com.quizlet.data.model.T0 r2 = new com.quizlet.data.model.T0     // Catch: java.lang.Exception -> L29
            java.lang.Object r3 = r1.getKey()     // Catch: java.lang.Exception -> L29
            java.lang.String r3 = (java.lang.String) r3     // Catch: java.lang.Exception -> L29
            java.lang.Object r1 = r1.getValue()     // Catch: java.lang.Exception -> L29
            java.util.List r1 = (java.util.List) r1     // Catch: java.lang.Exception -> L29
            r2.<init>(r3, r1)     // Catch: java.lang.Exception -> L29
            r9.add(r2)     // Catch: java.lang.Exception -> L29
            goto Lb4
        Ld5:
            return r9
        Ld6:
            com.quizlet.data.exceptions.practicetests.PracticeTestsException r0 = new com.quizlet.data.exceptions.practicetests.PracticeTestsException
            java.lang.String r9 = r9.getMessage()
            r0.<init>(r9)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.course.e.d(kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object e(long r12, kotlin.coroutines.jvm.internal.c r14) throws java.lang.Throwable {
        /*
            r11 = this;
            boolean r0 = r14 instanceof com.quizlet.data.interactor.course.d
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.data.interactor.course.d r0 = (com.quizlet.data.interactor.course.d) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.course.d r0 = new com.quizlet.data.interactor.course.d
            r0.<init>(r11, r14)
        L18:
            java.lang.Object r14 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.data.interactor.course.e r12 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r14)     // Catch: java.lang.Exception -> L5a
            goto L56
        L29:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r13 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r13)
            throw r12
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            java.lang.Object r14 = r11.b     // Catch: java.lang.Exception -> L59
            r9 = r14
            androidx.work.impl.model.n r9 = (androidx.work.impl.model.n) r9     // Catch: java.lang.Exception -> L59
            long r7 = r11.a     // Catch: java.lang.Exception -> L59
            r0.j = r11     // Catch: java.lang.Exception -> L59
            r0.m = r3     // Catch: java.lang.Exception -> L59
            com.quizlet.remote.model.course.f r4 = new com.quizlet.remote.model.course.f     // Catch: java.lang.Exception -> L59
            r10 = 0
            r5 = r12
            r4.<init>(r5, r7, r9, r10)     // Catch: java.lang.Exception -> L59
            java.lang.Object r12 = r9.d     // Catch: java.lang.Exception -> L59
            kotlinx.coroutines.y r12 = (kotlinx.coroutines.AbstractC5040y) r12     // Catch: java.lang.Exception -> L59
            java.lang.Object r12 = kotlinx.coroutines.E.J(r12, r4, r0)     // Catch: java.lang.Exception -> L59
            if (r12 != r1) goto L51
            goto L53
        L51:
            kotlin.Unit r12 = kotlin.Unit.a     // Catch: java.lang.Exception -> L59
        L53:
            if (r12 != r1) goto L56
            return r1
        L56:
            kotlin.Unit r12 = kotlin.Unit.a
            return r12
        L59:
            r12 = r11
        L5a:
            java.lang.Object r12 = r12.c
            org.slf4j.b r12 = (org.slf4j.b) r12
            java.lang.String r13 = "Exception in the DeleteCourseMembershipUseCase while deleting the course membership."
            r12.m(r13)
            com.quizlet.data.repository.course.exceptions.DeleteCourseMembershipException r12 = new com.quizlet.data.repository.course.exceptions.DeleteCourseMembershipException
            java.lang.String r13 = "Could not delete course membership."
            r12.<init>(r13)
            throw r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.course.e.e(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public String identity() {
        return "SetPageDeepLink";
    }

    public e(n repository, org.slf4j.b logger, long j) {
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = repository;
        this.c = logger;
        this.a = j;
    }

    public e(C3 practiceTestsRepository, long j, o timestampFormatter) {
        Intrinsics.checkNotNullParameter(practiceTestsRepository, "practiceTestsRepository");
        Intrinsics.checkNotNullParameter(timestampFormatter, "timestampFormatter");
        this.b = practiceTestsRepository;
        this.a = j;
        this.c = timestampFormatter;
    }

    public e() {
        this.b = new m();
        this.c = new m();
    }
}
