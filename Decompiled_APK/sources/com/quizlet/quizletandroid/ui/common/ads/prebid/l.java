package com.quizlet.quizletandroid.ui.common.ads.prebid;

import android.view.ViewGroup;
import android.view.WindowManager;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import kotlin.Unit;
import kotlin.collections.L;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public L j;
    public ArrayList k;
    public int l;
    public final /* synthetic */ ViewGroup m;
    public final /* synthetic */ List n;
    public final /* synthetic */ m o;
    public final /* synthetic */ int p;
    public final /* synthetic */ String q;
    public final /* synthetic */ WindowManager r;
    public final /* synthetic */ boolean s;
    public final /* synthetic */ Map t;
    public final /* synthetic */ Function0 u;
    public final /* synthetic */ Function1 v;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(ViewGroup viewGroup, List list, m mVar, int i, String str, WindowManager windowManager, boolean z, Map map, Function0 function0, Function1 function1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = viewGroup;
        this.n = list;
        this.o = mVar;
        this.p = i;
        this.q = str;
        this.r = windowManager;
        this.s = z;
        this.t = map;
        this.u = function0;
        this.v = function1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new l(this.m, this.n, this.o, this.p, this.q, this.r, this.s, this.t, this.u, this.v, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((l) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x00a4, code lost:
    
        if (kotlinx.coroutines.E.J(r3, r3, r19) == r1) goto L16;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r20) {
        /*
            r19 = this;
            r0 = r19
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            com.quizlet.quizletandroid.ui.common.ads.prebid.m r4 = r0.o
            android.view.ViewGroup r3 = r0.m
            r5 = 2
            r6 = 1
            if (r2 == 0) goto L30
            if (r2 == r6) goto L1f
            if (r2 != r5) goto L17
            androidx.glance.appwidget.protobuf.Z.e(r20)
            goto La7
        L17:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L1f:
            java.util.ArrayList r2 = r0.k
            kotlin.collections.L r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r20)
            r7 = r20
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r7 = r7.a
            r13 = r6
            r6 = r7
            r7 = r2
            goto L53
        L30:
            androidx.glance.appwidget.protobuf.Z.e(r20)
            kotlin.collections.L r2 = kotlin.collections.V.c()
            java.util.List r7 = kotlin.collections.A.b(r3)
            java.util.List r8 = r0.n
            java.util.ArrayList r7 = kotlin.collections.CollectionsKt.c0(r7, r8)
            r0.j = r2
            r0.k = r7
            r0.l = r6
            int r6 = r0.p
            java.lang.String r8 = r0.q
            java.lang.Object r6 = com.quizlet.quizletandroid.ui.common.ads.prebid.m.a(r4, r6, r8, r0)
            if (r6 != r1) goto L52
            goto La6
        L52:
            r13 = r2
        L53:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.Pair r6 = (kotlin.Pair) r6
            java.lang.Object r2 = r6.a
            com.quizlet.quizletandroid.ui.common.ads.a r2 = (com.quizlet.quizletandroid.ui.common.ads.C4634a) r2
            java.lang.Object r6 = r6.b
            r11 = r6
            java.util.Map r11 = (java.util.Map) r11
            com.quizlet.data.repository.searchexplanations.c r6 = r4.f
            com.quizlet.quizletandroid.ui.common.ads.i r8 = new com.quizlet.quizletandroid.ui.common.ads.i
            com.quizlet.ads.c r9 = r2.a
            android.view.WindowManager r10 = r0.r
            r8.<init>(r3, r10, r9)
            java.lang.Object r3 = r6.a(r8)
            r8 = r3
            com.google.android.gms.ads.h r8 = (com.google.android.gms.ads.h) r8
            kotlinx.coroutines.y r3 = r4.d
            r6 = r3
            com.quizlet.quizletandroid.ui.common.ads.prebid.k r3 = new com.quizlet.quizletandroid.ui.common.ads.prebid.k
            java.util.Map r12 = r0.t
            kotlin.jvm.functions.Function0 r14 = r0.u
            r9 = r6
            boolean r6 = r0.s
            r10 = r9
            android.view.ViewGroup r9 = r0.m
            r15 = r10
            android.view.WindowManager r10 = r0.r
            r16 = r15
            kotlin.jvm.functions.Function1 r15 = r0.v
            r17 = r16
            r16 = 0
            r18 = r5
            r5 = r2
            r2 = r18
            r18 = r17
            r3.<init>(r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16)
            r4 = 0
            r0.j = r4
            r0.k = r4
            r0.l = r2
            r15 = r18
            java.lang.Object r2 = kotlinx.coroutines.E.J(r15, r3, r0)
            if (r2 != r1) goto La7
        La6:
            return r1
        La7:
            kotlin.Unit r1 = kotlin.Unit.a
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.common.ads.prebid.l.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
