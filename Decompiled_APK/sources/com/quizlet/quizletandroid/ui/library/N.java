package com.quizlet.quizletandroid.ui.library;

import com.quizlet.data.model.EnumC4164s0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class N extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ EnumC4164s0 k;
    public final /* synthetic */ c0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public N(EnumC4164s0 enumC4164s0, c0 c0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = enumC4164s0;
        this.l = c0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new N(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((N) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0049, code lost:
    
        if (r8.emit(r1, r7) == r0) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x0056, code lost:
    
        if (r8.emit(r1, r7) == r0) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x0063, code lost:
    
        if (r8.emit(r1, r7) == r0) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x0070, code lost:
    
        if (r8.emit(r1, r7) == r0) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x007d, code lost:
    
        if (r8.emit(r1, r7) == r0) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x007f, code lost:
    
        return r0;
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
            r2 = 5
            r3 = 4
            r4 = 3
            r5 = 2
            r6 = 1
            if (r1 == 0) goto L21
            if (r1 == r6) goto L15
            if (r1 == r5) goto L15
            if (r1 == r4) goto L15
            if (r1 == r3) goto L15
            if (r1 != r2) goto L19
        L15:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L80
        L19:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L21:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.data.model.s0 r8 = r7.k
            int r8 = r8.ordinal()
            com.quizlet.quizletandroid.ui.library.c0 r1 = r7.l
            if (r8 == 0) goto L73
            if (r8 == r6) goto L66
            if (r8 == r5) goto L59
            if (r8 == r4) goto L4c
            if (r8 == r3) goto L3f
            if (r8 != r2) goto L39
            goto L80
        L39:
            kotlin.NoWhenBranchMatchedException r8 = new kotlin.NoWhenBranchMatchedException
            r8.<init>()
            throw r8
        L3f:
            kotlinx.coroutines.flow.d0 r8 = r1.u
            com.quizlet.quizletandroid.ui.library.data.y r1 = com.quizlet.quizletandroid.ui.library.data.y.a
            r7.j = r2
            java.lang.Object r8 = r8.emit(r1, r7)
            if (r8 != r0) goto L80
            goto L7f
        L4c:
            kotlinx.coroutines.flow.d0 r8 = r1.u
            com.quizlet.quizletandroid.ui.library.data.v r1 = com.quizlet.quizletandroid.ui.library.data.v.a
            r7.j = r6
            java.lang.Object r8 = r8.emit(r1, r7)
            if (r8 != r0) goto L80
            goto L7f
        L59:
            kotlinx.coroutines.flow.d0 r8 = r1.u
            com.quizlet.quizletandroid.ui.library.data.w r1 = com.quizlet.quizletandroid.ui.library.data.w.a
            r7.j = r5
            java.lang.Object r8 = r8.emit(r1, r7)
            if (r8 != r0) goto L80
            goto L7f
        L66:
            kotlinx.coroutines.flow.d0 r8 = r1.u
            com.quizlet.quizletandroid.ui.library.data.x r1 = com.quizlet.quizletandroid.ui.library.data.x.a
            r7.j = r3
            java.lang.Object r8 = r8.emit(r1, r7)
            if (r8 != r0) goto L80
            goto L7f
        L73:
            kotlinx.coroutines.flow.d0 r8 = r1.u
            com.quizlet.quizletandroid.ui.library.data.E r1 = com.quizlet.quizletandroid.ui.library.data.E.a
            r7.j = r4
            java.lang.Object r8 = r8.emit(r1, r7)
            if (r8 != r0) goto L80
        L7f:
            return r0
        L80:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.library.N.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
