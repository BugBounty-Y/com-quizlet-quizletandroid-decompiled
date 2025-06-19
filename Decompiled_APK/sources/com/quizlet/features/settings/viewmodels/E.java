package com.quizlet.features.settings.viewmodels;

import com.quizlet.data.model.C4135i0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class E extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public s0 j;
    public I k;
    public Object l;
    public com.quizlet.features.settings.data.models.f m;
    public String n;
    public String o;
    public com.quizlet.features.settings.data.states.y p;
    public boolean q;
    public boolean r;
    public boolean s;
    public int t;
    public /* synthetic */ Object u;
    public final /* synthetic */ I v;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(I i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.v = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        E e = new E(this.v, hVar);
        e.u = obj;
        return e;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((E) create((C4135i0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x00e9, code lost:
    
        if (r2 == r1) goto L33;
     */
    /* JADX WARN: Removed duplicated region for block: B:10:0x003a A[PHI: r2 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15
  0x003a: PHI (r2v13 boolean) = (r2v10 boolean), (r2v21 boolean) binds: [B:24:0x00a2, B:9:0x001d] A[DONT_GENERATE, DONT_INLINE]
  0x003a: PHI (r5v6 java.lang.Object) = (r5v5 java.lang.Object), (r5v9 java.lang.Object) binds: [B:24:0x00a2, B:9:0x001d] A[DONT_GENERATE, DONT_INLINE]
  0x003a: PHI (r6v2 boolean) = (r6v1 boolean), (r6v3 boolean) binds: [B:24:0x00a2, B:9:0x001d] A[DONT_GENERATE, DONT_INLINE]
  0x003a: PHI (r7v1 boolean) = (r7v0 boolean), (r7v2 boolean) binds: [B:24:0x00a2, B:9:0x001d] A[DONT_GENERATE, DONT_INLINE]
  0x003a: PHI (r8v2 com.quizlet.features.settings.data.states.y) = (r8v1 com.quizlet.features.settings.data.states.y), (r8v3 com.quizlet.features.settings.data.states.y) binds: [B:24:0x00a2, B:9:0x001d] A[DONT_GENERATE, DONT_INLINE]
  0x003a: PHI (r9v1 java.lang.String) = (r9v0 java.lang.String), (r9v2 java.lang.String) binds: [B:24:0x00a2, B:9:0x001d] A[DONT_GENERATE, DONT_INLINE]
  0x003a: PHI (r10v1 java.lang.String) = (r10v0 java.lang.String), (r10v2 java.lang.String) binds: [B:24:0x00a2, B:9:0x001d] A[DONT_GENERATE, DONT_INLINE]
  0x003a: PHI (r11v1 com.quizlet.features.settings.data.models.f) = (r11v0 com.quizlet.features.settings.data.models.f), (r11v2 com.quizlet.features.settings.data.models.f) binds: [B:24:0x00a2, B:9:0x001d] A[DONT_GENERATE, DONT_INLINE]
  0x003a: PHI (r12v1 java.lang.Object) = (r12v0 java.lang.Object), (r12v2 java.lang.Object) binds: [B:24:0x00a2, B:9:0x001d] A[DONT_GENERATE, DONT_INLINE]
  0x003a: PHI (r13v2 com.quizlet.features.settings.viewmodels.I) = (r13v1 com.quizlet.features.settings.viewmodels.I), (r13v3 com.quizlet.features.settings.viewmodels.I) binds: [B:24:0x00a2, B:9:0x001d] A[DONT_GENERATE, DONT_INLINE]
  0x003a: PHI (r14v2 kotlinx.coroutines.flow.s0) = (r14v1 kotlinx.coroutines.flow.s0), (r14v3 kotlinx.coroutines.flow.s0) binds: [B:24:0x00a2, B:9:0x001d] A[DONT_GENERATE, DONT_INLINE]
  0x003a: PHI (r15v2 com.quizlet.data.model.i0) = (r15v1 com.quizlet.data.model.i0), (r15v4 com.quizlet.data.model.i0) binds: [B:24:0x00a2, B:9:0x001d] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0062  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00ef  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:24:0x00a2 -> B:10:0x003a). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r31) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 242
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.settings.viewmodels.E.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
