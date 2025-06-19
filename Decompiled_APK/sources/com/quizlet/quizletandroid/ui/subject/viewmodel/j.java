package com.quizlet.quizletandroid.ui.subject.viewmodel;

import com.quizlet.generated.enums.I1;
import com.quizlet.generated.enums.K1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public m j;
    public int k;
    public final /* synthetic */ m l;
    public final /* synthetic */ I1 m;
    public final /* synthetic */ K1 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(m mVar, I1 i1, K1 k1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = mVar;
        this.m = i1;
        this.n = k1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0042, code lost:
    
        if (com.quizlet.quizletandroid.ui.subject.viewmodel.m.B(r4, r6, r5) == r0) goto L20;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.k
            r2 = 2
            r3 = 1
            com.quizlet.quizletandroid.ui.subject.viewmodel.m r4 = r5.l
            if (r1 == 0) goto L20
            if (r1 == r3) goto L1a
            if (r1 != r2) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.util.NoSuchElementException -> L45
            goto L4c
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            com.quizlet.quizletandroid.ui.subject.viewmodel.m r1 = r5.j
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.util.NoSuchElementException -> L45
            goto L33
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.onetrust.otpublishers.headless.UI.fragment.q r6 = r4.c     // Catch: java.util.NoSuchElementException -> L45
            com.quizlet.generated.enums.I1 r1 = r5.m     // Catch: java.util.NoSuchElementException -> L45
            r5.j = r4     // Catch: java.util.NoSuchElementException -> L45
            r5.k = r3     // Catch: java.util.NoSuchElementException -> L45
            java.lang.Object r6 = r6.g(r1, r5)     // Catch: java.util.NoSuchElementException -> L45
            if (r6 != r0) goto L32
            goto L44
        L32:
            r1 = r4
        L33:
            com.quizlet.features.subjects.model.b r6 = (com.quizlet.features.subjects.model.b) r6     // Catch: java.util.NoSuchElementException -> L45
            r1.i = r6     // Catch: java.util.NoSuchElementException -> L45
            com.quizlet.generated.enums.K1 r6 = r5.n     // Catch: java.util.NoSuchElementException -> L45
            r1 = 0
            r5.j = r1     // Catch: java.util.NoSuchElementException -> L45
            r5.k = r2     // Catch: java.util.NoSuchElementException -> L45
            java.lang.Object r6 = com.quizlet.quizletandroid.ui.subject.viewmodel.m.B(r4, r6, r5)     // Catch: java.util.NoSuchElementException -> L45
            if (r6 != r0) goto L4c
        L44:
            return r0
        L45:
            androidx.lifecycle.Y r6 = r4.f
            com.quizlet.quizletandroid.ui.subject.viewmodel.e r0 = com.quizlet.quizletandroid.ui.subject.viewmodel.e.a
            r6.j(r0)
        L4c:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.subject.viewmodel.j.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
