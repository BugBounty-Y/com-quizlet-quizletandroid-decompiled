package com.quizlet.edgy.ui.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.edgy.ui.viewmodel.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4201b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C4204e k;
    public final /* synthetic */ String l;
    public final /* synthetic */ String m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4201b(C4204e c4204e, String str, String str2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c4204e;
        this.l = str;
        this.m = str2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4201b(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4201b) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x003f, code lost:
    
        if (r1.emit(r2, r5) == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) throws java.lang.Throwable {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.j
            com.quizlet.edgy.ui.viewmodel.e r2 = r5.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L42
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L30
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.onetrust.otpublishers.headless.UI.fragment.q r6 = r2.c
            r5.j = r4
            java.lang.String r1 = r5.l
            java.lang.String r4 = r5.m
            java.lang.Object r6 = r6.n(r1, r4, r5)
            if (r6 != r0) goto L30
            goto L41
        L30:
            com.quizlet.data.model.Course r6 = (com.quizlet.data.model.Course) r6
            kotlinx.coroutines.flow.d0 r1 = r2.d
            com.quizlet.edgy.ui.viewmodel.a r2 = new com.quizlet.edgy.ui.viewmodel.a
            r2.<init>(r6)
            r5.j = r3
            java.lang.Object r6 = r1.emit(r2, r5)
            if (r6 != r0) goto L42
        L41:
            return r0
        L42:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.edgy.ui.viewmodel.C4201b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
