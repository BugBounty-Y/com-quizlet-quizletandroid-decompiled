package com.quizlet.data.repository.selectedterm;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes2.dex */
public final class c extends i implements Function2 {
    public J j;
    public Object k;
    public Object l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ f o;
    public final /* synthetic */ long p;
    public final /* synthetic */ long q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(f fVar, long j, long j2, h hVar) {
        super(2, hVar);
        this.o = fVar;
        this.p = j;
        this.q = j2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        c cVar = new c(this.o, this.p, this.q, hVar);
        cVar.n = obj;
        return cVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((InterfaceC5002j) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x00c4, code lost:
    
        if (r4.emit(r13, r5) == r7) goto L40;
     */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0081  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x00ac  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00d3 A[PHI: r2 r3 r4 r5 r6
  0x00d3: PHI (r2v2 java.lang.Object) = (r2v4 java.lang.Object), (r2v5 java.lang.Object) binds: [B:31:0x00d1, B:23:0x00aa] A[DONT_GENERATE, DONT_INLINE]
  0x00d3: PHI (r3v1 kotlin.jvm.internal.J) = (r3v3 kotlin.jvm.internal.J), (r3v4 kotlin.jvm.internal.J) binds: [B:31:0x00d1, B:23:0x00aa] A[DONT_GENERATE, DONT_INLINE]
  0x00d3: PHI (r4v0 kotlinx.coroutines.flow.j) = (r4v1 kotlinx.coroutines.flow.j), (r4v2 kotlinx.coroutines.flow.j) binds: [B:31:0x00d1, B:23:0x00aa] A[DONT_GENERATE, DONT_INLINE]
  0x00d3: PHI (r5v2 com.quizlet.data.repository.selectedterm.c) = (r5v3 com.quizlet.data.repository.selectedterm.c), (r5v4 com.quizlet.data.repository.selectedterm.c) binds: [B:31:0x00d1, B:23:0x00aa] A[DONT_GENERATE, DONT_INLINE]
  0x00d3: PHI (r6v1 com.quizlet.data.repository.selectedterm.f) = (r6v2 com.quizlet.data.repository.selectedterm.f), (r6v3 com.quizlet.data.repository.selectedterm.f) binds: [B:31:0x00d1, B:23:0x00aa] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00dc  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x010a  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0112  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0117  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:41:0x010a -> B:9:0x0022). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:43:0x0112 -> B:16:0x007d). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r18) {
        /*
            Method dump skipped, instructions count: 282
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.selectedterm.c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
