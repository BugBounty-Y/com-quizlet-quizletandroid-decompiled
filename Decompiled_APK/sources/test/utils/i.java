package test.utils;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public List j;
    public Iterator k;
    public List l;
    public int m;
    public int n;
    public int o;
    public final /* synthetic */ ArrayList p;
    public final /* synthetic */ ArrayList q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(ArrayList arrayList, ArrayList arrayList2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.p = arrayList;
        this.q = arrayList2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.p, this.q, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0034  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x005c  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:16:0x0051 -> B:17:0x0052). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.o
            r2 = 1
            if (r1 == 0) goto L1f
            if (r1 != r2) goto L17
            int r1 = r7.n
            int r3 = r7.m
            java.util.List r4 = r7.l
            java.util.Iterator r5 = r7.k
            java.util.List r6 = r7.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L52
        L17:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1f:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.util.ArrayList r8 = r7.p
            java.util.Iterator r8 = r8.iterator()
            java.util.ArrayList r1 = r7.q
            r3 = 0
            r5 = r8
            r4 = r1
        L2d:
            r1 = r3
            boolean r8 = r5.hasNext()
            if (r8 == 0) goto L5c
            java.lang.Object r8 = r5.next()
            int r3 = r1 + 1
            if (r1 < 0) goto L57
            kotlinx.coroutines.H r8 = (kotlinx.coroutines.H) r8
            r7.j = r4
            r7.k = r5
            r7.l = r4
            r7.m = r3
            r7.n = r1
            r7.o = r2
            java.lang.Object r8 = r8.Y(r7)
            if (r8 != r0) goto L51
            return r0
        L51:
            r6 = r4
        L52:
            r4.set(r1, r8)
            r4 = r6
            goto L2d
        L57:
            kotlin.collections.B.p()
            r8 = 0
            throw r8
        L5c:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: test.utils.i.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
