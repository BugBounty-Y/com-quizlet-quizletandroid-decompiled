package com.quizlet.quizletandroid.ui.classcreation;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ i k;
    public final /* synthetic */ String l;
    public final /* synthetic */ String m;
    public final /* synthetic */ boolean n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(i iVar, String str, String str2, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
        this.l = str;
        this.m = str2;
        this.n = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x007c, code lost:
    
        if (r8.emit(r1, r7) == r0) goto L24;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) throws com.quizlet.data.exceptions.classcreation.ClassCreationMissingTitleException {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.j
            r2 = 2
            r3 = 1
            com.quizlet.quizletandroid.ui.classcreation.i r4 = r7.k
            if (r1 == 0) goto L1e
            if (r1 == r3) goto L1a
            if (r1 != r2) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L7f
        L12:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L69
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            kotlinx.coroutines.flow.s0 r8 = r4.f
        L23:
            java.lang.Object r1 = r8.getValue()
            r5 = r1
            com.quizlet.quizletandroid.ui.classcreation.data.j r5 = (com.quizlet.quizletandroid.ui.classcreation.data.j) r5
            com.quizlet.quizletandroid.ui.classcreation.data.i r5 = com.quizlet.quizletandroid.ui.classcreation.data.i.a
            boolean r1 = r8.k(r1, r5)
            if (r1 == 0) goto L23
            com.quizlet.offline.managers.b r8 = r4.c
            com.quizlet.offline.managers.i r8 = (com.quizlet.offline.managers.i) r8
            boolean r8 = r8.i
            if (r8 != 0) goto L58
        L3a:
            kotlinx.coroutines.flow.s0 r8 = r4.f
            java.lang.Object r0 = r8.getValue()
            r1 = r0
            com.quizlet.quizletandroid.ui.classcreation.data.j r1 = (com.quizlet.quizletandroid.ui.classcreation.data.j) r1
            com.quizlet.quizletandroid.ui.classcreation.data.f r1 = new com.quizlet.quizletandroid.ui.classcreation.data.f
            com.quizlet.quizletandroid.ui.classcreation.data.a r2 = com.quizlet.quizletandroid.ui.classcreation.data.a.a
            java.lang.String r3 = "errorType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r3)
            r1.<init>()
            boolean r8 = r8.k(r0, r1)
            if (r8 == 0) goto L3a
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        L58:
            r7.j = r3
            java.lang.String r8 = r7.m
            boolean r1 = r7.n
            com.quizlet.data.repository.folderwithcreatorinclass.e r3 = r4.b
            java.lang.String r5 = r7.l
            java.lang.Object r8 = r3.f(r5, r8, r7, r1)
            if (r8 != r0) goto L69
            goto L7e
        L69:
            java.lang.Number r8 = (java.lang.Number) r8
            long r5 = r8.longValue()
            kotlinx.coroutines.flow.d0 r8 = r4.d
            com.quizlet.quizletandroid.ui.classcreation.data.d r1 = new com.quizlet.quizletandroid.ui.classcreation.data.d
            r1.<init>(r5)
            r7.j = r2
            java.lang.Object r8 = r8.emit(r1, r7)
            if (r8 != r0) goto L7f
        L7e:
            return r0
        L7f:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.classcreation.h.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
