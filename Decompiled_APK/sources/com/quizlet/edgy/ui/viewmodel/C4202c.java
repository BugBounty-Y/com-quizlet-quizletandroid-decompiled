package com.quizlet.edgy.ui.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.edgy.ui.viewmodel.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4202c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public C4204e j;
    public int k;
    public final /* synthetic */ C4204e l;
    public final /* synthetic */ String m;
    public final /* synthetic */ String n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4202c(C4204e c4204e, String str, String str2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c4204e;
        this.m = str;
        this.n = str2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4202c(this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4202c) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:28:0x0077, code lost:
    
        if (r8.emit(r1, r7) != r0) goto L30;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) throws java.lang.Throwable {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.k
            com.quizlet.edgy.ui.viewmodel.e r2 = r7.l
            r3 = 0
            r4 = 2
            r5 = 1
            if (r1 == 0) goto L21
            if (r1 == r5) goto L1b
            if (r1 != r4) goto L13
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L7a
        L13:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1b:
            com.quizlet.edgy.ui.viewmodel.e r1 = r7.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L5f
        L21:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.data.model.Course r8 = r2.e
            if (r8 == 0) goto L2b
            java.lang.String r8 = r8.e
            goto L2c
        L2b:
            r8 = r3
        L2c:
            java.lang.String r1 = r7.m
            boolean r8 = kotlin.jvm.internal.Intrinsics.b(r8, r1)
            java.lang.String r6 = r7.n
            if (r8 == 0) goto L44
            com.quizlet.data.model.Course r8 = r2.e
            if (r8 == 0) goto L3d
            java.lang.String r8 = r8.b
            goto L3e
        L3d:
            r8 = r3
        L3e:
            boolean r8 = kotlin.jvm.internal.Intrinsics.b(r8, r6)
            if (r8 != 0) goto L63
        L44:
            r7.j = r2
            r7.k = r5
            com.google.firebase.crashlytics.internal.settings.b r8 = r2.b
            java.lang.Object r8 = r8.b
            androidx.work.impl.model.n r8 = (androidx.work.impl.model.n) r8
            com.quizlet.remote.model.course.d r5 = new com.quizlet.remote.model.course.d
            r5.<init>(r8, r1, r6, r3)
            java.lang.Object r8 = r8.d
            kotlinx.coroutines.y r8 = (kotlinx.coroutines.AbstractC5040y) r8
            java.lang.Object r8 = kotlinx.coroutines.E.J(r8, r5, r7)
            if (r8 != r0) goto L5e
            goto L79
        L5e:
            r1 = r2
        L5f:
            com.quizlet.data.model.Course r8 = (com.quizlet.data.model.Course) r8
            r1.e = r8
        L63:
            kotlinx.coroutines.flow.d0 r8 = r2.d
            com.quizlet.edgy.ui.viewmodel.a r1 = new com.quizlet.edgy.ui.viewmodel.a
            com.quizlet.data.model.Course r2 = r2.e
            kotlin.jvm.internal.Intrinsics.d(r2)
            r1.<init>(r2)
            r7.j = r3
            r7.k = r4
            java.lang.Object r8 = r8.emit(r1, r7)
            if (r8 != r0) goto L7a
        L79:
            return r0
        L7a:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.edgy.ui.viewmodel.C4202c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
