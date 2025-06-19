package com.quizlet.features.notes.upload.viewmodels;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public k j;
    public Collection k;
    public Iterator l;
    public Collection m;
    public int n;
    public final /* synthetic */ List o;
    public final /* synthetic */ k p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(k kVar, List list, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.o = list;
        this.p = kVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.p, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0040  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0071  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:14:0x0065 -> B:15:0x0066). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) throws java.lang.Throwable {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.n
            com.quizlet.features.notes.upload.viewmodels.k r2 = r8.p
            r3 = 1
            if (r1 == 0) goto L23
            if (r1 != r3) goto L1b
            java.util.Collection r1 = r8.m
            java.util.Collection r1 = (java.util.Collection) r1
            java.util.Iterator r4 = r8.l
            java.util.Collection r5 = r8.k
            java.util.Collection r5 = (java.util.Collection) r5
            com.quizlet.features.notes.upload.viewmodels.k r6 = r8.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L66
        L1b:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L23:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.util.ArrayList r9 = new java.util.ArrayList
            java.util.List r1 = r8.o
            r4 = 10
            int r4 = kotlin.collections.C.q(r1, r4)
            r9.<init>(r4)
            java.util.Iterator r1 = r1.iterator()
            r4 = r1
            r6 = r2
            r1 = r9
        L3a:
            boolean r9 = r4.hasNext()
            if (r9 == 0) goto L71
            java.lang.Object r9 = r4.next()
            android.net.Uri r9 = (android.net.Uri) r9
            com.quizlet.data.repository.set.f r5 = r6.w
            java.lang.String r9 = r9.toString()
            java.lang.String r7 = "toString(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, r7)
            r8.j = r6
            r7 = r1
            java.util.Collection r7 = (java.util.Collection) r7
            r8.k = r7
            r8.l = r4
            r8.m = r7
            r8.n = r3
            java.lang.Object r9 = r5.d(r9, r8)
            if (r9 != r0) goto L65
            return r0
        L65:
            r5 = r1
        L66:
            java.lang.String r9 = (java.lang.String) r9
            android.net.Uri r9 = android.net.Uri.parse(r9)
            r1.add(r9)
            r1 = r5
            goto L3a
        L71:
            java.util.List r1 = (java.util.List) r1
            r2.O(r1)
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.upload.viewmodels.g.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
