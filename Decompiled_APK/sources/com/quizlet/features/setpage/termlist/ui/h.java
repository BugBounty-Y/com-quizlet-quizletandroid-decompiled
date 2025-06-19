package com.quizlet.features.setpage.termlist.ui;

import androidx.compose.runtime.InterfaceC0773a0;
import com.quizlet.features.setpage.termlist.data.n;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ n j;
    public final /* synthetic */ InterfaceC0773a0 k;
    public final /* synthetic */ InterfaceC0773a0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(n nVar, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = nVar;
        this.k = interfaceC0773a0;
        this.l = interfaceC0773a02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0040  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) {
        /*
            r8 = this;
            r0 = 1
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.features.setpage.termlist.data.n r9 = r8.j
            java.util.List r1 = r9.a
            java.util.ArrayList r2 = new java.util.ArrayList
            r2.<init>()
            java.util.Iterator r1 = r1.iterator()
        L13:
            boolean r3 = r1.hasNext()
            if (r3 == 0) goto L47
            java.lang.Object r3 = r1.next()
            r4 = r3
            com.quizlet.features.setpage.termlist.data.j r4 = (com.quizlet.features.setpage.termlist.data.j) r4
            com.quizlet.features.setpage.termlist.data.b r5 = r9.f
            boolean r5 = r5.e
            if (r5 == 0) goto L40
            java.util.Set r5 = r9.c
            r6 = r5
            java.util.Collection r6 = (java.util.Collection) r6
            if (r6 == 0) goto L40
            boolean r6 = r6.isEmpty()
            if (r6 == 0) goto L34
            goto L40
        L34:
            long r6 = r4.a
            java.lang.Long r4 = new java.lang.Long
            r4.<init>(r6)
            boolean r4 = r5.contains(r4)
            goto L41
        L40:
            r4 = r0
        L41:
            if (r4 == 0) goto L13
            r2.add(r3)
            goto L13
        L47:
            androidx.compose.runtime.a0 r9 = r8.k
            java.lang.Object r9 = r9.getValue()
            java.util.List r9 = (java.util.List) r9
            java.lang.String r1 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r1)
            java.lang.String r1 = "adsList"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r1)
            java.util.ArrayList r1 = kotlin.collections.CollectionsKt.y0(r2)
            r3 = 3
            r4 = 0
        L5f:
            int r5 = r2.size()
            if (r3 >= r5) goto L76
            int r5 = r9.size()
            if (r4 >= r5) goto L76
            java.lang.Object r5 = r9.get(r4)
            r1.add(r3, r5)
            int r3 = r3 + 12
            int r4 = r4 + r0
            goto L5f
        L76:
            androidx.compose.runtime.a0 r9 = r8.l
            r9.setValue(r1)
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.termlist.ui.h.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
