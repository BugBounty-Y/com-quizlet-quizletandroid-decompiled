package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final com.google.firebase.crashlytics.internal.settings.b a;
    public final com.quizlet.data.interactor.school.b b;
    public final com.quizlet.data.interactor.school.e c;
    public final com.quizlet.data.repository.qclass.c d;
    public final androidx.work.impl.model.c e;

    public i(com.google.firebase.crashlytics.internal.settings.b createNewSchoolUseCase, com.quizlet.data.interactor.school.b createSchoolMembershipUseCase, com.quizlet.data.interactor.school.e deleteSchoolMembershipUseCase, com.quizlet.data.repository.qclass.c schoolMembershipUseCase, androidx.work.impl.model.c userProperties) {
        Intrinsics.checkNotNullParameter(createNewSchoolUseCase, "createNewSchoolUseCase");
        Intrinsics.checkNotNullParameter(createSchoolMembershipUseCase, "createSchoolMembershipUseCase");
        Intrinsics.checkNotNullParameter(deleteSchoolMembershipUseCase, "deleteSchoolMembershipUseCase");
        Intrinsics.checkNotNullParameter(schoolMembershipUseCase, "schoolMembershipUseCase");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        this.a = createNewSchoolUseCase;
        this.b = createSchoolMembershipUseCase;
        this.c = deleteSchoolMembershipUseCase;
        this.d = schoolMembershipUseCase;
        this.e = userProperties;
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x007e, code lost:
    
        if (r9.m(r4, r2, r0) != r1) goto L38;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r7 = this;
            boolean r0 = r9 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.d
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.d r0 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.d) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.d r0 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.d
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 3
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L4e
            if (r2 == r5) goto L45
            if (r2 == r4) goto L3b
            if (r2 != r3) goto L33
            java.lang.Object r8 = r0.j
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e r8 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e) r8
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Exception -> L31
            goto L81
        L31:
            r8 = move-exception
            goto L84
        L33:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L3b:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e r8 = r0.k
            java.lang.Object r2 = r0.j
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i r2 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i) r2
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Exception -> L31
            goto L6d
        L45:
            java.lang.Object r8 = r0.j
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i r8 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i) r8
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Exception -> L31
            r2 = r8
            goto L5d
        L4e:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r7     // Catch: java.lang.Exception -> L31
            r0.n = r5     // Catch: java.lang.Exception -> L31
            java.lang.Object r9 = r7.e(r8, r0)     // Catch: java.lang.Exception -> L31
            if (r9 != r1) goto L5c
            goto L80
        L5c:
            r2 = r7
        L5d:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e r9 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e) r9     // Catch: java.lang.Exception -> L31
            r0.j = r2     // Catch: java.lang.Exception -> L31
            r0.k = r9     // Catch: java.lang.Exception -> L31
            r0.n = r4     // Catch: java.lang.Exception -> L31
            java.lang.Object r8 = r2.b(r0)     // Catch: java.lang.Exception -> L31
            if (r8 != r1) goto L6c
            goto L80
        L6c:
            r8 = r9
        L6d:
            com.quizlet.data.interactor.school.b r9 = r2.b     // Catch: java.lang.Exception -> L31
            long r4 = r8.a     // Catch: java.lang.Exception -> L31
            com.quizlet.generated.enums.U1 r2 = com.quizlet.generated.enums.U1.MAIN     // Catch: java.lang.Exception -> L31
            r0.j = r8     // Catch: java.lang.Exception -> L31
            r6 = 0
            r0.k = r6     // Catch: java.lang.Exception -> L31
            r0.n = r3     // Catch: java.lang.Exception -> L31
            java.lang.Object r9 = r9.m(r4, r2, r0)     // Catch: java.lang.Exception -> L31
            if (r9 != r1) goto L81
        L80:
            return r1
        L81:
            kotlin.p r9 = kotlin.r.b     // Catch: java.lang.Exception -> L31
            return r8
        L84:
            kotlin.p r9 = kotlin.r.b
            kotlin.q r8 = androidx.glance.appwidget.protobuf.Z.b(r8)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i.a(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x0069, code lost:
    
        if (r9.b(r5, r0) == r1) goto L27;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(kotlin.coroutines.jvm.internal.c r9) throws com.quizlet.data.repository.school.exceptions.SchoolMembershipException {
        /*
            r8 = this;
            boolean r0 = r9 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.e
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.e r0 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.e) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.e r0 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.e
            r0.<init>(r8, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L6c
        L2a:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L32:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L49
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r8
            r0.m = r4
            com.quizlet.data.repository.qclass.c r9 = r8.d
            java.lang.Object r9 = r9.m(r0)
            if (r9 != r1) goto L48
            goto L6b
        L48:
            r2 = r8
        L49:
            com.quizlet.data.model.w1 r9 = (com.quizlet.data.model.C4177w1) r9
            r4 = 0
            if (r9 == 0) goto L58
            com.quizlet.data.model.School r9 = r9.a
            java.lang.Long r5 = new java.lang.Long
            long r6 = r9.a
            r5.<init>(r6)
            goto L59
        L58:
            r5 = r4
        L59:
            if (r5 == 0) goto L6c
            long r5 = r5.longValue()
            com.quizlet.data.interactor.school.e r9 = r2.c
            r0.j = r4
            r0.m = r3
            java.lang.Object r9 = r9.b(r5, r0)
            if (r9 != r1) goto L6c
        L6b:
            return r1
        L6c:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i.b(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.f
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.f r0 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.f r0 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.f
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r5)     // Catch: java.lang.Throwable -> L27
            goto L3f
        L27:
            r5 = move-exception
            goto L44
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlin.p r5 = kotlin.r.b     // Catch: java.lang.Throwable -> L27
            r0.l = r3     // Catch: java.lang.Throwable -> L27
            java.lang.Object r5 = r4.b(r0)     // Catch: java.lang.Throwable -> L27
            if (r5 != r1) goto L3f
            return r1
        L3f:
            kotlin.Unit r5 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L27
            kotlin.p r0 = kotlin.r.b     // Catch: java.lang.Throwable -> L27
            return r5
        L44:
            kotlin.p r0 = kotlin.r.b
            kotlin.q r5 = androidx.glance.appwidget.protobuf.Z.b(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i.c(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.g
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.g r0 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.g) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.g r0 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.g
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r5)     // Catch: java.lang.Throwable -> L27
            goto L41
        L27:
            r5 = move-exception
            goto L50
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlin.p r5 = kotlin.r.b     // Catch: java.lang.Throwable -> L27
            com.quizlet.data.repository.qclass.c r5 = r4.d     // Catch: java.lang.Throwable -> L27
            r0.l = r3     // Catch: java.lang.Throwable -> L27
            java.lang.Object r5 = r5.m(r0)     // Catch: java.lang.Throwable -> L27
            if (r5 != r1) goto L41
            return r1
        L41:
            com.quizlet.data.model.w1 r5 = (com.quizlet.data.model.C4177w1) r5     // Catch: java.lang.Throwable -> L27
            if (r5 == 0) goto L4c
            com.quizlet.data.model.School r5 = r5.a     // Catch: java.lang.Throwable -> L27
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e r5 = com.google.android.gms.internal.mlkit_vision_barcode.W5.d(r5)     // Catch: java.lang.Throwable -> L27
            goto L4d
        L4c:
            r5 = 0
        L4d:
            kotlin.p r0 = kotlin.r.b     // Catch: java.lang.Throwable -> L27
            return r5
        L50:
            kotlin.p r0 = kotlin.r.b
            kotlin.q r5 = androidx.glance.appwidget.protobuf.Z.b(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i.d(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:31:0x0079, code lost:
    
        if (r9 == r0) goto L32;
     */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object e(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r7 = this;
            boolean r0 = r9 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.h
            if (r0 == 0) goto L14
            r0 = r9
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.h r0 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.h) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.n = r1
        L12:
            r6 = r0
            goto L1a
        L14:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.h r0 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.h
            r0.<init>(r7, r9)
            goto L12
        L1a:
            java.lang.Object r9 = r6.l
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.n
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L3c
            if (r1 == r3) goto L34
            if (r1 != r2) goto L2c
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L7c
        L2c:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L34:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e r8 = r6.k
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i r1 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L55
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.d r9 = r8.i
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.d r1 = com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.d.a
            if (r9 != r1) goto L82
            r6.j = r7
            r6.k = r8
            r6.n = r3
            androidx.work.impl.model.c r9 = r7.e
            java.lang.Enum r9 = r9.d(r6)
            if (r9 != r0) goto L54
            goto L7b
        L54:
            r1 = r7
        L55:
            com.quizlet.generated.enums.H r9 = (com.quizlet.generated.enums.H) r9
            com.google.firebase.crashlytics.internal.settings.b r1 = r1.a
            java.lang.String r8 = r8.b
            if (r9 == 0) goto L66
            java.lang.String r9 = r9.b()
            if (r9 != 0) goto L64
            goto L66
        L64:
            r5 = r9
            goto L69
        L66:
            java.lang.String r9 = ""
            goto L64
        L69:
            r9 = 0
            r6.j = r9
            r6.k = r9
            r6.n = r2
            java.lang.String r3 = ""
            java.lang.String r4 = ""
            r2 = r8
            java.lang.Object r9 = r1.g(r2, r3, r4, r5, r6)
            if (r9 != r0) goto L7c
        L7b:
            return r0
        L7c:
            com.quizlet.data.model.School r9 = (com.quizlet.data.model.School) r9
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e r8 = com.google.android.gms.internal.mlkit_vision_barcode.W5.d(r9)
        L82:
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i.e(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
