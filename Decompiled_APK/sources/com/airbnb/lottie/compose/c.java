package com.airbnb.lottie.compose;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ l k;
    public final /* synthetic */ InterfaceC5025j0 l;
    public final /* synthetic */ int m;
    public final /* synthetic */ int n;
    public final /* synthetic */ h o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(l lVar, InterfaceC5025j0 interfaceC5025j0, int i, int i2, h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = lVar;
        this.l = interfaceC5025j0;
        this.m = i;
        this.n = i2;
        this.o = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /*  JADX ERROR: JadxOverflowException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxOverflowException: Regions count limit reached
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0026  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x003d  */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0048  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0065  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.j
            r2 = 1
            if (r1 == 0) goto L15
            if (r1 != r2) goto Ld
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L5d
        Ld:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L15:
            androidx.glance.appwidget.protobuf.Z.e(r6)
        L18:
            int[] r6 = com.airbnb.lottie.compose.b.a
            com.airbnb.lottie.compose.l r1 = r5.k
            int r1 = r1.ordinal()
            r6 = r6[r1]
            int r1 = r5.m
            if (r6 != r2) goto L31
            kotlinx.coroutines.j0 r6 = r5.l
            boolean r6 = r6.a()
            if (r6 == 0) goto L2f
            goto L31
        L2f:
            int r1 = r5.n
        L31:
            r5.j = r2
            com.airbnb.lottie.compose.h r6 = r5.o
            r6.getClass()
            r3 = 2147483647(0x7fffffff, float:NaN)
            if (r1 != r3) goto L48
            com.airbnb.lottie.compose.e r3 = new com.airbnb.lottie.compose.e
            r4 = 0
            r3.<init>(r6, r1, r4)
            java.lang.Object r6 = androidx.compose.animation.core.AbstractC0240f.t(r3, r5)
            goto L5a
        L48:
            com.airbnb.lottie.compose.e r3 = new com.airbnb.lottie.compose.e
            r4 = 1
            r3.<init>(r6, r1, r4)
            kotlin.coroutines.CoroutineContext r6 = r5.getContext()
            androidx.compose.runtime.W r6 = androidx.compose.runtime.C0776c.r(r6)
            java.lang.Object r6 = r6.P(r3, r5)
        L5a:
            if (r6 != r0) goto L5d
            return r0
        L5d:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 != 0) goto L18
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.compose.c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
