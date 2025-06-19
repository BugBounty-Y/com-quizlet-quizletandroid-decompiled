package com.quizlet.features.setpage.studypreview.ui;

import androidx.compose.foundation.pager.C0466e;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0466e k;
    public final /* synthetic */ com.quizlet.features.setpage.studypreview.g l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(C0466e c0466e, com.quizlet.features.setpage.studypreview.g gVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0466e;
        this.l = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0052, code lost:
    
        if (r8.b(r1, r7) == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.j
            com.quizlet.features.setpage.studypreview.g r2 = r7.l
            androidx.compose.foundation.pager.e r3 = r7.k
            r4 = 2
            r5 = 1
            if (r1 == 0) goto L20
            if (r1 == r5) goto L1c
            if (r1 != r4) goto L14
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L55
        L14:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L3c
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.features.notes.detail.composables.magicnotesdetail.l r8 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.l
            r1 = 1
            r8.<init>(r3, r1)
            androidx.datastore.core.t r8 = androidx.compose.runtime.C0776c.F(r8)
            com.quizlet.features.setpage.studypreview.ui.h r1 = new com.quizlet.features.setpage.studypreview.ui.h
            r6 = 0
            r1.<init>(r2, r6)
            r7.j = r5
            java.lang.Object r8 = r8.b(r1, r7)
            if (r8 != r0) goto L3c
            goto L54
        L3c:
            com.quizlet.features.notes.detail.composables.magicnotesdetail.l r8 = new com.quizlet.features.notes.detail.composables.magicnotesdetail.l
            r1 = 2
            r8.<init>(r3, r1)
            androidx.datastore.core.t r8 = androidx.compose.runtime.C0776c.F(r8)
            com.quizlet.features.setpage.studypreview.ui.h r1 = new com.quizlet.features.setpage.studypreview.ui.h
            r3 = 1
            r1.<init>(r2, r3)
            r7.j = r4
            java.lang.Object r8 = r8.b(r1, r7)
            if (r8 != r0) goto L55
        L54:
            return r0
        L55:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.studypreview.ui.i.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
