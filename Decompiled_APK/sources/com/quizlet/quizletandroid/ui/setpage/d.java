package com.quizlet.quizletandroid.ui.setpage;

import android.view.ViewGroup;
import android.view.WindowManager;
import androidx.lifecycle.C;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.data.interactor.set.c k;
    public final /* synthetic */ C l;
    public final /* synthetic */ WindowManager m;
    public final /* synthetic */ int n;
    public final /* synthetic */ com.quizlet.features.setpage.shareset.a o;
    public final /* synthetic */ ViewGroup p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(com.quizlet.data.interactor.set.c cVar, C c, WindowManager windowManager, int i, com.quizlet.features.setpage.shareset.a aVar, ViewGroup viewGroup, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = c;
        this.m = windowManager;
        this.n = i;
        this.o = aVar;
        this.p = viewGroup;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.k, this.l, this.m, this.n, this.o, this.p, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0053, code lost:
    
        if (com.quizlet.data.interactor.set.c.g(r2, r12.l, r12.m, r12.n, r12.o, r7, r8, r9, r10, r12) == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.j
            com.quizlet.data.interactor.set.c r2 = r12.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L56
        L12:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L2e
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            java.lang.Object r13 = r2.c
            com.quizlet.data.repository.user.a r13 = (com.quizlet.data.repository.user.a) r13
            r12.j = r4
            java.lang.Object r13 = r13.j(r12)
            if (r13 != r0) goto L2e
            goto L55
        L2e:
            java.lang.Boolean r13 = (java.lang.Boolean) r13
            boolean r8 = r13.booleanValue()
            com.quizlet.login.magiclink.ui.e r9 = new com.quizlet.login.magiclink.ui.e
            android.view.ViewGroup r7 = r12.p
            r13 = 22
            r9.<init>(r7, r13)
            com.quizlet.quizletandroid.ui.common.ads.G r10 = new com.quizlet.quizletandroid.ui.common.ads.G
            r13 = 13
            r10.<init>(r7, r13)
            r12.j = r3
            int r5 = r12.n
            com.quizlet.features.setpage.shareset.a r6 = r12.o
            androidx.lifecycle.C r3 = r12.l
            android.view.WindowManager r4 = r12.m
            r11 = r12
            java.lang.Object r13 = com.quizlet.data.interactor.set.c.g(r2, r3, r4, r5, r6, r7, r8, r9, r10, r11)
            if (r13 != r0) goto L56
        L55:
            return r0
        L56:
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.d.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
