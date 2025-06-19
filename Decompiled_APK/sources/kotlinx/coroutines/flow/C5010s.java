package kotlinx.coroutines.flow;

import kotlin.Unit;

/* renamed from: kotlinx.coroutines.flow.s, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5010s extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public kotlin.jvm.internal.J j;
    public kotlin.jvm.internal.I k;
    public int l;
    public /* synthetic */ Object m;
    public /* synthetic */ Object n;
    public final /* synthetic */ com.braze.requests.framework.m o;
    public final /* synthetic */ InterfaceC4992i p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5010s(com.braze.requests.framework.m mVar, InterfaceC4992i interfaceC4992i, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.o = mVar;
        this.p = interfaceC4992i;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        C5010s c5010s = new C5010s(this.o, this.p, (kotlin.coroutines.h) obj3);
        c5010s.m = (kotlinx.coroutines.C) obj;
        c5010s.n = (InterfaceC5002j) obj2;
        return c5010s.invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:38:0x0111, code lost:
    
        if (r11.c(r18) == r1) goto L39;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x001c, code lost:
    
        if (r11.d(r18) == r1) goto L39;
     */
    /* JADX WARN: Removed duplicated region for block: B:14:0x005c  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0096 A[PHI: r6 r7 r8 r9
  0x0096: PHI (r6v3 kotlin.jvm.internal.J) = (r6v5 kotlin.jvm.internal.J), (r6v6 kotlin.jvm.internal.J), (r6v6 kotlin.jvm.internal.J) binds: [B:26:0x0093, B:15:0x0061, B:18:0x0079] A[DONT_GENERATE, DONT_INLINE]
  0x0096: PHI (r7v3 kotlinx.coroutines.channels.w) = (r7v5 kotlinx.coroutines.channels.w), (r7v6 kotlinx.coroutines.channels.w), (r7v6 kotlinx.coroutines.channels.w) binds: [B:26:0x0093, B:15:0x0061, B:18:0x0079] A[DONT_GENERATE, DONT_INLINE]
  0x0096: PHI (r8v2 kotlinx.coroutines.flow.j) = (r8v15 kotlinx.coroutines.flow.j), (r8v16 kotlinx.coroutines.flow.j), (r8v16 kotlinx.coroutines.flow.j) binds: [B:26:0x0093, B:15:0x0061, B:18:0x0079] A[DONT_GENERATE, DONT_INLINE]
  0x0096: PHI (r9v0 kotlin.jvm.internal.I) = (r9v3 kotlin.jvm.internal.I), (r9v5 kotlin.jvm.internal.I), (r9v5 kotlin.jvm.internal.I) binds: [B:26:0x0093, B:15:0x0061, B:18:0x0079] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00b0  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x00d4  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0108  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x010d  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0114  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r19) {
        /*
            Method dump skipped, instructions count: 279
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.C5010s.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
