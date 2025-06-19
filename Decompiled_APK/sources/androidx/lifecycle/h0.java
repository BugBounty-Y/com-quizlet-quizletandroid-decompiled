package androidx.lifecycle;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class h0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlin.jvm.internal.J j;
    public kotlin.jvm.internal.J k;
    public int l;
    public final /* synthetic */ C m;
    public final /* synthetic */ B n;
    public final /* synthetic */ kotlinx.coroutines.C o;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public h0(C c, B b, kotlinx.coroutines.C c2, Function2 function2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = c;
        this.n = b;
        this.o = c2;
        this.p = (kotlin.coroutines.jvm.internal.i) function2;
    }

    /* JADX WARN: Type inference failed for: r4v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h0(this.m, this.n, this.o, this.p, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x00a1 A[Catch: all -> 0x00c5, TRY_LEAVE, TryCatch #0 {all -> 0x00c5, blocks: (B:17:0x003c, B:25:0x0073, B:34:0x008c, B:36:0x00a1, B:30:0x0082, B:32:0x0086, B:33:0x0089, B:22:0x006b, B:23:0x006e, B:24:0x0071), top: B:59:0x003c }] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00ad A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00b6  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x00bf  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00cd  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00d6  */
    /* JADX WARN: Removed duplicated region for block: B:63:? A[SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r12v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r14) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 218
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.lifecycle.h0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
