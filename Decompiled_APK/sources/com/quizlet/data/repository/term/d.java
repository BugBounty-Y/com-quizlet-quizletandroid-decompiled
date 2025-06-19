package com.quizlet.data.repository.term;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes2.dex */
public final class d extends i implements Function2 {
    public J j;
    public Object k;
    public Object l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ g o;
    public final /* synthetic */ long p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(g gVar, long j, h hVar) {
        super(2, hVar);
        this.o = gVar;
        this.p = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        d dVar = new d(this.o, this.p, hVar);
        dVar.n = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((InterfaceC5002j) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:27:0x00b6, code lost:
    
        if (r14.emit(r10, r17) == r1) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x012b, code lost:
    
        if (r12.emit(r14, r17) == r1) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x010c, code lost:
    
        r2 = r13;
     */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0080  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x009e  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00c6 A[PHI: r12 r13 r14
  0x00c6: PHI (r12v2 java.lang.Object) = (r12v5 java.lang.Object), (r12v6 java.lang.Object) binds: [B:33:0x00c4, B:25:0x009c] A[DONT_GENERATE, DONT_INLINE]
  0x00c6: PHI (r13v2 kotlin.jvm.internal.J) = (r13v3 kotlin.jvm.internal.J), (r13v4 kotlin.jvm.internal.J) binds: [B:33:0x00c4, B:25:0x009c] A[DONT_GENERATE, DONT_INLINE]
  0x00c6: PHI (r14v6 kotlinx.coroutines.flow.j) = (r14v9 kotlinx.coroutines.flow.j), (r14v10 kotlinx.coroutines.flow.j) binds: [B:33:0x00c4, B:25:0x009c] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00cd  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00f0  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00f5  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0112  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0133  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0135  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:56:0x0133 -> B:55:0x0130). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r18) {
        /*
            Method dump skipped, instructions count: 312
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.term.d.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
