package androidx.datastore.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: androidx.datastore.core.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1088u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public C1071c j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ P m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1088u(P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1088u c1088u = new C1088u(this.m, hVar);
        c1088u.l = obj;
        return c1088u;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1088u) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:35:0x00c6, code lost:
    
        if (r10 == r0) goto L36;
     */
    /* JADX WARN: Removed duplicated region for block: B:31:0x00bd  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00cc  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 222
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.C1088u.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
