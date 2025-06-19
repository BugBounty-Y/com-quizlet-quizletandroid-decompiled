package com.quizlet.data.interactor.folder;

import com.google.android.gms.measurement.internal.J;
import com.quizlet.data.model.F0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ long k;
    public final /* synthetic */ long l;
    public final /* synthetic */ J m;
    public final /* synthetic */ String n;
    public final /* synthetic */ F0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(long j, long j2, J j3, String str, F0 f0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = j;
        this.l = j2;
        this.m = j3;
        this.n = str;
        this.o = f0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x004c, code lost:
    
        if (r12 == r0) goto L26;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x00ce, code lost:
    
        if (r12 == r0) goto L26;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r12) throws java.lang.Exception {
        /*
            r11 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r11.j
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L1d
            if (r1 == r3) goto L19
            if (r1 != r2) goto L11
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto Ld1
        L11:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r0)
            throw r12
        L19:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L50
        L1d:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            long r4 = r11.k
            r6 = 0
            int r12 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            com.google.android.gms.measurement.internal.J r1 = r11.m
            if (r12 <= 0) goto L5f
            r12 = r2
            r8 = r3
            long r2 = r11.l
            int r6 = (r2 > r6 ? 1 : (r2 == r6 ? 0 : -1))
            if (r6 <= 0) goto L5d
            java.lang.Object r12 = r1.d
            r9 = r12
            androidx.work.impl.model.n r9 = (androidx.work.impl.model.n) r9
            r11.j = r8
            r6 = r1
            com.quizlet.remote.model.course.e r1 = new com.quizlet.remote.model.course.e
            r10 = 0
            long r6 = r6.b
            java.lang.String r8 = r11.n
            r1.<init>(r2, r4, r6, r8, r9, r10)
            java.lang.Object r12 = r9.d
            kotlinx.coroutines.y r12 = (kotlinx.coroutines.AbstractC5040y) r12
            java.lang.Object r12 = kotlinx.coroutines.E.J(r12, r1, r11)
            if (r12 != r0) goto L50
            goto Ld0
        L50:
            com.quizlet.data.model.d0 r12 = (com.quizlet.data.model.AbstractC4119d0) r12
            if (r12 == 0) goto L55
            return r12
        L55:
            java.lang.Exception r12 = new java.lang.Exception
            java.lang.String r0 = "Could not create a course folder"
            r12.<init>(r0)
            throw r12
        L5d:
            r6 = r1
            goto L62
        L5f:
            r12 = r2
            r8 = r3
            goto L5d
        L62:
            java.lang.Object r1 = r6.c
            com.quizlet.data.repository.folder.i r1 = (com.quizlet.data.repository.folder.i) r1
            com.quizlet.data.model.F0 r2 = r11.o
            java.lang.String r3 = "folder"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r3)
            androidx.work.impl.model.c r4 = r1.a
            java.lang.Object r4 = r4.b
            com.quizlet.local.ormlite.models.bookmark.a r4 = (com.quizlet.local.ormlite.models.bookmark.a) r4
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r3)
            java.lang.String r3 = "data"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r3)
            java.lang.String r3 = r2.b
            java.lang.String r5 = r2.c
            long r6 = r2.a
            com.quizlet.db.data.models.persisted.DBFolder r2 = com.quizlet.db.data.models.persisted.DBFolder.create(r6, r3, r5)
            java.lang.String r3 = "create(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r3)
            r2.setDirty(r8)
            java.lang.Object r3 = r4.b
            com.quizlet.db.data.models.identity.ModelIdentityProvider r3 = (com.quizlet.db.data.models.identity.ModelIdentityProvider) r3
            java.util.List r2 = kotlin.collections.A.b(r2)
            io.reactivex.rxjava3.core.p r2 = r3.generateLocalIdsIfNeededAsync(r2)
            com.google.android.material.floatingactionbutton.c r3 = new com.google.android.material.floatingactionbutton.c
            r5 = 28
            r3.<init>(r4, r5)
            io.reactivex.rxjava3.internal.operators.single.g r2 = r2.e(r3)
            java.lang.String r3 = "flatMap(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r3)
            io.reactivex.rxjava3.internal.operators.single.g r2 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3770y6.a(r2)
            com.google.android.material.floatingactionbutton.c r4 = new com.google.android.material.floatingactionbutton.c
            r5 = 13
            r4.<init>(r1, r5)
            io.reactivex.rxjava3.internal.operators.single.g r1 = r2.e(r4)
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r3)
            io.reactivex.rxjava3.internal.operators.maybe.h r1 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3770y6.b(r1)
            io.reactivex.rxjava3.internal.operators.maybe.w r1 = r1.h()
            java.lang.String r2 = "toSingle(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r2)
            r11.j = r12
            java.lang.Object r12 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r1, r11)
            if (r12 != r0) goto Ld1
        Ld0:
            return r0
        Ld1:
            kotlin.jvm.internal.Intrinsics.d(r12)
            com.quizlet.data.model.d0 r12 = (com.quizlet.data.model.AbstractC4119d0) r12
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folder.h.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
