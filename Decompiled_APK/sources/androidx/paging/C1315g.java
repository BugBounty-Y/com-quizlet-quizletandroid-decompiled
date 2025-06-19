package androidx.paging;

import java.util.Iterator;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: androidx.paging.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1315g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Iterator j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ com.quizlet.remote.model.notes.e m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1315g(com.quizlet.remote.model.notes.e eVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1315g c1315g = new C1315g(this.m, hVar);
        c1315g.l = obj;
        return c1315g;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1315g) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x003c, code lost:
    
        if (r6 == r0) goto L18;
     */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0054  */
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
            com.quizlet.remote.model.notes.e r2 = r5.m
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L28
            if (r1 == r4) goto L20
            if (r1 != r3) goto L18
            java.util.Iterator r1 = r5.j
            java.lang.Object r2 = r5.l
            kotlinx.coroutines.flow.j r2 = (kotlinx.coroutines.flow.InterfaceC5002j) r2
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4e
        L18:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L20:
            java.lang.Object r1 = r5.l
            kotlinx.coroutines.flow.j r1 = (kotlinx.coroutines.flow.InterfaceC5002j) r1
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L3f
        L28:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r5.l
            r1 = r6
            kotlinx.coroutines.flow.j r1 = (kotlinx.coroutines.flow.InterfaceC5002j) r1
            java.lang.Object r6 = r2.b
            androidx.appcompat.widget.z r6 = (androidx.appcompat.widget.C0122z) r6
            r5.l = r1
            r5.k = r4
            java.io.Serializable r6 = r6.r(r5)
            if (r6 != r0) goto L3f
            goto L66
        L3f:
            java.util.List r6 = (java.util.List) r6
            java.lang.Object r2 = r2.e
            kotlinx.coroutines.y0 r2 = (kotlinx.coroutines.y0) r2
            r2.start()
            java.util.Iterator r6 = r6.iterator()
            r2 = r1
            r1 = r6
        L4e:
            boolean r6 = r1.hasNext()
            if (r6 == 0) goto L67
            java.lang.Object r6 = r1.next()
            kotlin.collections.IndexedValue r6 = (kotlin.collections.IndexedValue) r6
            r5.l = r2
            r5.j = r1
            r5.k = r3
            java.lang.Object r6 = r2.emit(r6, r5)
            if (r6 != r0) goto L4e
        L66:
            return r0
        L67:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.C1315g.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
