package com.quizlet.shared.usecase.studiableMetadata;

import assistantMode.enums.s;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public d j;
    public Collection k;
    public Iterator l;
    public s m;
    public Collection n;
    public long o;
    public int p;
    public final /* synthetic */ List q;
    public final /* synthetic */ d r;
    public final /* synthetic */ long s;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(List list, d dVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.q = list;
        this.r = dVar;
        this.s = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.q, this.r, this.s, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0092  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:22:0x0087 -> B:23:0x0088). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r12) {
        /*
            r11 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r11.p
            r2 = 10
            r3 = 1
            if (r1 == 0) goto L27
            if (r1 != r3) goto L1f
            long r4 = r11.o
            java.util.Collection r1 = r11.n
            java.util.Collection r1 = (java.util.Collection) r1
            assistantMode.enums.s r6 = r11.m
            java.util.Iterator r7 = r11.l
            java.util.Collection r8 = r11.k
            java.util.Collection r8 = (java.util.Collection) r8
            com.quizlet.shared.usecase.studiableMetadata.d r9 = r11.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L88
        L1f:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r0)
            throw r12
        L27:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            java.util.ArrayList r12 = new java.util.ArrayList
            r12.<init>()
            java.util.List r1 = r11.q
            java.util.Iterator r1 = r1.iterator()
        L35:
            boolean r4 = r1.hasNext()
            if (r4 == 0) goto L4e
            java.lang.Object r4 = r1.next()
            r5 = r4
            assistantMode.enums.s r5 = (assistantMode.enums.s) r5
            assistantMode.enums.s r6 = assistantMode.enums.s.b
            if (r5 == r6) goto L35
            assistantMode.enums.s r6 = assistantMode.enums.s.c
            if (r5 == r6) goto L35
            r12.add(r4)
            goto L35
        L4e:
            java.util.ArrayList r1 = new java.util.ArrayList
            int r4 = kotlin.collections.C.q(r12, r2)
            r1.<init>(r4)
            java.util.Iterator r12 = r12.iterator()
            com.quizlet.shared.usecase.studiableMetadata.d r4 = r11.r
            long r5 = r11.s
            r7 = r12
            r9 = r4
            r4 = r5
        L62:
            boolean r12 = r7.hasNext()
            if (r12 == 0) goto L92
            java.lang.Object r12 = r7.next()
            r6 = r12
            assistantMode.enums.s r6 = (assistantMode.enums.s) r6
            r11.j = r9
            r12 = r1
            java.util.Collection r12 = (java.util.Collection) r12
            r11.k = r12
            r11.l = r7
            r11.m = r6
            r11.n = r12
            r11.o = r4
            r11.p = r3
            java.lang.Object r12 = r9.a(r6, r4, r11)
            if (r12 != r0) goto L87
            return r0
        L87:
            r8 = r1
        L88:
            kotlin.Pair r10 = new kotlin.Pair
            r10.<init>(r6, r12)
            r1.add(r10)
            r1 = r8
            goto L62
        L92:
            java.util.List r1 = (java.util.List) r1
            int r12 = kotlin.collections.C.q(r1, r2)
            int r12 = kotlin.collections.U.a(r12)
            r0 = 16
            if (r12 >= r0) goto La1
            r12 = r0
        La1:
            java.util.LinkedHashMap r0 = new java.util.LinkedHashMap
            r0.<init>(r12)
            java.util.Iterator r12 = r1.iterator()
        Laa:
            boolean r1 = r12.hasNext()
            if (r1 == 0) goto Lc9
            java.lang.Object r1 = r12.next()
            kotlin.Pair r1 = (kotlin.Pair) r1
            java.lang.Object r2 = r1.a
            assistantMode.refactored.types.StudiableMetadataContent r3 = new assistantMode.refactored.types.StudiableMetadataContent
            java.lang.Object r1 = r1.b
            assistantMode.refactored.types.StudiableMetadataContent r1 = (assistantMode.refactored.types.StudiableMetadataContent) r1
            java.util.List r4 = r1.a
            assistantMode.enums.q r1 = r1.b
            r3.<init>(r4, r1)
            r0.put(r2, r3)
            goto Laa
        Lc9:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.studiableMetadata.c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
