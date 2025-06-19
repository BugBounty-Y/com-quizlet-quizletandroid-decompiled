package com.quizlet.features.setpage.viewmodel;

import com.quizlet.data.model.A0;
import com.quizlet.data.model.InterfaceC4156p0;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.X;

/* loaded from: classes3.dex */
public final class H extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public A0 j;
    public A0 k;
    public InterfaceC4156p0 l;
    public InterfaceC4156p0 m;
    public X n;
    public P o;
    public Object p;
    public List q;
    public List r;
    public List s;
    public int t;
    public final /* synthetic */ P u;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public H(P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.u = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new H(this.u, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((H) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:20:0x00f5 A[PHI: r2 r5
  0x00f5: PHI (r2v8 com.quizlet.data.model.A0) = (r2v6 com.quizlet.data.model.A0), (r2v10 com.quizlet.data.model.A0) binds: [B:18:0x00f2, B:12:0x00b1] A[DONT_GENERATE, DONT_INLINE]
  0x00f5: PHI (r5v4 java.lang.Object) = (r5v3 java.lang.Object), (r5v7 java.lang.Object) binds: [B:18:0x00f2, B:12:0x00b1] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0109  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0124  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0178  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x017b  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x01cf  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x01d2  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x021f  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0258  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x02d1  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x02d4  */
    /* JADX WARN: Removed duplicated region for block: B:52:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:53:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r7v5, types: [kotlinx.coroutines.flow.X] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:44:0x0258 -> B:45:0x025b). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r23) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 758
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.viewmodel.H.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
