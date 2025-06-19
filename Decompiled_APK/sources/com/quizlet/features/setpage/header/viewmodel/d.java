package com.quizlet.features.setpage.header.viewmodel;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ f k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(f fVar, h hVar) {
        super(2, hVar);
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0058, code lost:
    
        if (kotlinx.coroutines.flow.e0.i((kotlinx.coroutines.flow.InterfaceC4992i) r2, r3, r18) == r1) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r19) throws java.lang.Throwable {
        /*
            r18 = this;
            r0 = r18
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.j
            com.quizlet.features.setpage.header.viewmodel.f r5 = r0.k
            r11 = 2
            r3 = 1
            if (r2 == 0) goto L22
            if (r2 == r3) goto L1c
            if (r2 != r11) goto L14
            androidx.glance.appwidget.protobuf.Z.e(r19)
            goto L5b
        L14:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r19)
            r2 = r19
            goto L42
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r19)
            r0.j = r3
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G r13 = r5.f
            r13.getClass()
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.E r12 = new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.E
            r17 = 0
            long r14 = r5.i
            io.reactivex.rxjava3.subjects.r r2 = r5.c
            r16 = r2
            r12.<init>(r13, r14, r16, r17)
            kotlinx.coroutines.y r2 = r13.d
            java.lang.Object r2 = kotlinx.coroutines.E.J(r2, r12, r0)
            if (r2 != r1) goto L42
            goto L5a
        L42:
            kotlinx.coroutines.flow.i r2 = (kotlinx.coroutines.flow.InterfaceC4992i) r2
            androidx.compose.runtime.internal.c r3 = new androidx.compose.runtime.internal.c
            java.lang.String r8 = "onStudyModeButtonViewUpdate(Lcom/quizlet/data/model/StudyModeButtonViewState;)V"
            r9 = 4
            r4 = 2
            java.lang.Class<com.quizlet.features.setpage.header.viewmodel.f> r6 = com.quizlet.features.setpage.header.viewmodel.f.class
            java.lang.String r7 = "onStudyModeButtonViewUpdate"
            r10 = 4
            r3.<init>(r4, r5, r6, r7, r8, r9, r10)
            r0.j = r11
            java.lang.Object r2 = kotlinx.coroutines.flow.e0.i(r2, r3, r0)
            if (r2 != r1) goto L5b
        L5a:
            return r1
        L5b:
            kotlin.Unit r1 = kotlin.Unit.a
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.header.viewmodel.d.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
