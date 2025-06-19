package androidx.compose.runtime;

import androidx.camera.camera2.internal.C0132i;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.runtime.t0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0828t0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public C0132i j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C0832v0 m;
    public final /* synthetic */ C0830u0 n;
    public final /* synthetic */ W o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0828t0(C0832v0 c0832v0, C0830u0 c0830u0, W w, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = c0832v0;
        this.n = c0830u0;
        this.o = w;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0828t0 c0828t0 = new C0828t0(this.m, this.n, this.o, hVar);
        c0828t0.l = obj;
        return c0828t0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0828t0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:102:0x0118 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:94:0x013e A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r5v7, types: [java.lang.Object, java.util.Collection] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r14) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 367
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0828t0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
