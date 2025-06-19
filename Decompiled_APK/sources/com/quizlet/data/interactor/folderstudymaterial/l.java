package com.quizlet.data.interactor.folderstudymaterial;

import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes2.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public List j;
    public J k;
    public Object l;
    public Object m;
    public int n;
    public /* synthetic */ Object o;
    public final /* synthetic */ o p;
    public final /* synthetic */ long q;
    public final /* synthetic */ List r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(o oVar, long j, List list, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.p = oVar;
        this.q = j;
        this.r = list;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        l lVar = new l(this.p, this.q, this.r, hVar);
        lVar.o = obj;
        return lVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((l) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:27:0x00ea, code lost:
    
        if (r4.emit(r15, r17) == r6) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x015b, code lost:
    
        if (r14.emit(r3, r17) == r6) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x013d, code lost:
    
        r0 = r2;
        r2 = r14;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0097 A[PHI: r0 r10 r14 r15
  0x0097: PHI (r0v21 kotlin.jvm.internal.J) = (r0v3 kotlin.jvm.internal.J), (r0v10 kotlin.jvm.internal.J), (r0v25 kotlin.jvm.internal.J) binds: [B:17:0x0076, B:35:0x0101, B:50:0x015e] A[DONT_GENERATE, DONT_INLINE]
  0x0097: PHI (r10v6 int) = (r10v0 int), (r10v2 int), (r10v7 int) binds: [B:17:0x0076, B:35:0x0101, B:50:0x015e] A[DONT_GENERATE, DONT_INLINE]
  0x0097: PHI (r14v8 kotlinx.coroutines.flow.j) = (r14v1 kotlinx.coroutines.flow.j), (r14v3 kotlinx.coroutines.flow.j), (r14v9 kotlinx.coroutines.flow.j) binds: [B:17:0x0076, B:35:0x0101, B:50:0x015e] A[DONT_GENERATE, DONT_INLINE]
  0x0097: PHI (r15v4 java.util.ArrayList) = (r15v1 java.util.ArrayList), (r15v2 java.util.ArrayList), (r15v5 java.util.ArrayList) binds: [B:17:0x0076, B:35:0x0101, B:50:0x015e] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:20:0x009b  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x00c7  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00fa A[PHI: r1 r2 r3 r4 r10
  0x00fa: PHI (r1v2 java.lang.Object) = (r1v4 java.lang.Object), (r1v5 java.lang.Object) binds: [B:33:0x00f8, B:25:0x00c5] A[DONT_GENERATE, DONT_INLINE]
  0x00fa: PHI (r2v4 kotlin.jvm.internal.J) = (r2v7 kotlin.jvm.internal.J), (r2v8 kotlin.jvm.internal.J) binds: [B:33:0x00f8, B:25:0x00c5] A[DONT_GENERATE, DONT_INLINE]
  0x00fa: PHI (r3v6 java.util.ArrayList) = (r3v23 java.util.ArrayList), (r3v24 java.util.ArrayList) binds: [B:33:0x00f8, B:25:0x00c5] A[DONT_GENERATE, DONT_INLINE]
  0x00fa: PHI (r4v2 kotlinx.coroutines.flow.j) = (r4v5 kotlinx.coroutines.flow.j), (r4v6 kotlinx.coroutines.flow.j) binds: [B:33:0x00f8, B:25:0x00c5] A[DONT_GENERATE, DONT_INLINE]
  0x00fa: PHI (r10v2 int) = (r10v4 int), (r10v5 int) binds: [B:33:0x00f8, B:25:0x00c5] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0103  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0123  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x0140  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0163  */
    /* JADX WARN: Type inference failed for: r1v1, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r1v10, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r1v14 */
    /* JADX WARN: Type inference failed for: r1v15, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r1v3 */
    /* JADX WARN: Type inference failed for: r1v9 */
    /* JADX WARN: Type inference failed for: r3v18, types: [java.util.List] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:35:0x0101 -> B:18:0x0097). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r18) {
        /*
            Method dump skipped, instructions count: 358
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folderstudymaterial.l.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
