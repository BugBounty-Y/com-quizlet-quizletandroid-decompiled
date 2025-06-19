package com.quizlet.edgy.ui.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class v extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public w j;
    public int k;
    public final /* synthetic */ w l;
    public final /* synthetic */ String m;
    public final /* synthetic */ String n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(w wVar, String str, String str2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = wVar;
        this.m = str;
        this.n = str2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new v(this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((v) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:37:0x0083, code lost:
    
        if (r13.emit(r1, r12) != r0) goto L39;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) throws java.lang.Throwable {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.k
            com.quizlet.edgy.ui.viewmodel.w r2 = r12.l
            r3 = 2
            r4 = 1
            r5 = 0
            if (r1 == 0) goto L24
            if (r1 == r4) goto L1d
            if (r1 != r3) goto L15
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r11 = r12
            goto L86
        L15:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L1d:
            com.quizlet.edgy.ui.viewmodel.w r1 = r12.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r11 = r12
            goto L6b
        L24:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            com.quizlet.data.model.School r13 = r2.j
            if (r13 == 0) goto L2e
            java.lang.String r13 = r13.i
            goto L2f
        L2e:
            r13 = r5
        L2f:
            java.lang.String r7 = r12.m
            boolean r13 = kotlin.jvm.internal.Intrinsics.b(r13, r7)
            java.lang.String r8 = r12.n
            if (r13 == 0) goto L4a
            com.quizlet.data.model.School r13 = r2.j
            if (r13 == 0) goto L40
            java.lang.String r13 = r13.b
            goto L41
        L40:
            r13 = r5
        L41:
            boolean r13 = kotlin.jvm.internal.Intrinsics.b(r13, r8)
            if (r13 != 0) goto L48
            goto L4a
        L48:
            r11 = r12
            goto L6f
        L4a:
            com.quizlet.edgy.model.State r13 = r2.e
            if (r13 == 0) goto L55
            java.lang.String r13 = r13.a
            if (r13 != 0) goto L53
            goto L55
        L53:
            r9 = r13
            goto L58
        L55:
            java.lang.String r13 = ""
            goto L53
        L58:
            com.quizlet.edgy.model.Country r13 = r2.d
            java.lang.String r10 = r13.a
            r12.j = r2
            r12.k = r4
            com.google.firebase.crashlytics.internal.settings.b r6 = r2.c
            r11 = r12
            java.lang.Object r13 = r6.g(r7, r8, r9, r10, r11)
            if (r13 != r0) goto L6a
            goto L85
        L6a:
            r1 = r2
        L6b:
            com.quizlet.data.model.School r13 = (com.quizlet.data.model.School) r13
            r1.j = r13
        L6f:
            kotlinx.coroutines.flow.d0 r13 = r2.i
            com.quizlet.edgy.ui.viewmodel.t r1 = new com.quizlet.edgy.ui.viewmodel.t
            com.quizlet.data.model.School r2 = r2.j
            kotlin.jvm.internal.Intrinsics.d(r2)
            r1.<init>(r2)
            r11.j = r5
            r11.k = r3
            java.lang.Object r13 = r13.emit(r1, r12)
            if (r13 != r0) goto L86
        L85:
            return r0
        L86:
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.edgy.ui.viewmodel.v.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
