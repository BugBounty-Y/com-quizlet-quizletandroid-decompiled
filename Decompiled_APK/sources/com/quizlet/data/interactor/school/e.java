package com.quizlet.data.interactor.school;

import android.os.Handler;
import android.text.TextUtils;
import com.google.ads.conversiontracking.r;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e {
    public long a;
    public final Object b;
    public final Object c;

    public e(com.quizlet.infra.legacysyncengine.net.c loader, com.quizlet.data.interactor.progress.c progressResetUseCase, long j) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(progressResetUseCase, "progressResetUseCase");
        this.b = loader;
        this.c = progressResetUseCase;
        this.a = j;
    }

    public static e a(String str) throws NumberFormatException {
        if (TextUtils.isEmpty(str)) {
            return null;
        }
        String[] strArrSplit = str.split(" ");
        if (strArrSplit.length != 3) {
            return null;
        }
        try {
            String str2 = strArrSplit[0];
            String str3 = strArrSplit[1];
            long j = Long.parseLong(strArrSplit[2]);
            e eVar = new e(j, str2, str3);
            long j2 = j + 7776000000L;
            HashMap map = r.a;
            if (j2 < System.currentTimeMillis()) {
                return null;
            }
            return eVar;
        } catch (NumberFormatException unused) {
            return null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(long r12, kotlin.coroutines.jvm.internal.c r14) throws java.lang.Throwable {
        /*
            r11 = this;
            boolean r0 = r14 instanceof com.quizlet.data.interactor.school.d
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.data.interactor.school.d r0 = (com.quizlet.data.interactor.school.d) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.school.d r0 = new com.quizlet.data.interactor.school.d
            r0.<init>(r11, r14)
        L18:
            java.lang.Object r14 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.data.interactor.school.e r12 = r0.j
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
            com.quizlet.data.repository.set.f r9 = (com.quizlet.data.repository.set.f) r9     // Catch: java.lang.Exception -> L59
            long r5 = r11.a     // Catch: java.lang.Exception -> L59
            r0.j = r11     // Catch: java.lang.Exception -> L59
            r0.m = r3     // Catch: java.lang.Exception -> L59
            com.quizlet.remote.model.school.d r4 = new com.quizlet.remote.model.school.d     // Catch: java.lang.Exception -> L59
            r10 = 0
            r7 = r12
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
            java.lang.String r13 = "Exception in the DeleteSchoolMembershipUseCase while deleting the school membership"
            r12.m(r13)
            com.quizlet.data.repository.school.exceptions.DeleteSchoolMembershipException r12 = new com.quizlet.data.repository.school.exceptions.DeleteSchoolMembershipException
            java.lang.String r13 = "Could not delete school membership."
            r12.<init>(r13)
            throw r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.school.e.b(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void c(boolean z) {
        if (z || System.currentTimeMillis() - this.a > 200) {
            ((Handler) this.b).removeCallbacksAndMessages(null);
            ((com.google.firebase.crashlytics.internal.common.i) this.c).run();
        }
    }

    public e(com.quizlet.data.repository.set.f repository, org.slf4j.b logger, long j) {
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = repository;
        this.c = logger;
        this.a = j;
    }

    public e(com.quizlet.quizletandroid.ui.studymodes.write.f fVar) {
        this.b = new Handler();
        this.c = new com.google.firebase.crashlytics.internal.common.i(29, this, fVar);
    }

    public e(long j, String str, String str2) {
        this.b = str;
        this.c = str2;
        this.a = j;
    }
}
