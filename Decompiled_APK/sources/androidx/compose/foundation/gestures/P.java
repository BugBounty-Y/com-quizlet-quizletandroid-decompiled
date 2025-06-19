package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class P extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlin.jvm.internal.J j;
    public kotlin.jvm.internal.J k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ Q n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public P(Q q, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = q;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        P p = new P(this.n, hVar);
        p.m = obj;
        return p;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((P) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:50:0x00e5, code lost:
    
        if (androidx.compose.foundation.gestures.Q.P0(r3, r6) != r0) goto L11;
     */
    /* JADX WARN: Path cross not found for [B:44:0x00c8, B:40:0x00b1], limit reached: 56 */
    /* JADX WARN: Path cross not found for [B:46:0x00cc, B:19:0x0056], limit reached: 56 */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0032 A[PHI: r1 r4
  0x0032: PHI (r1v11 kotlin.jvm.internal.J) = (r1v3 kotlin.jvm.internal.J), (r1v16 kotlin.jvm.internal.J) binds: [B:13:0x002f, B:36:0x00a8] A[DONT_GENERATE, DONT_INLINE]
  0x0032: PHI (r4v6 kotlinx.coroutines.C) = (r4v4 kotlinx.coroutines.C), (r4v7 kotlinx.coroutines.C) binds: [B:13:0x002f, B:36:0x00a8] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0056 A[PHI: r5
  0x0056: PHI (r5v7 kotlinx.coroutines.C) = 
  (r5v0 kotlinx.coroutines.C)
  (r5v3 kotlinx.coroutines.C)
  (r5v3 kotlinx.coroutines.C)
  (r5v3 kotlinx.coroutines.C)
  (r5v5 kotlinx.coroutines.C)
  (r5v8 kotlinx.coroutines.C)
 binds: [B:18:0x004e, B:45:0x00ca, B:47:0x00d7, B:41:0x00c3, B:30:0x0082, B:11:0x0027] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:21:0x005c  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00b1 A[Catch: CancellationException -> 0x00c6, TryCatch #2 {CancellationException -> 0x00c6, blocks: (B:38:0x00ab, B:40:0x00b1, B:44:0x00c8, B:46:0x00cc), top: B:59:0x00ab }] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00c8 A[Catch: CancellationException -> 0x00c6, TryCatch #2 {CancellationException -> 0x00c6, blocks: (B:38:0x00ab, B:40:0x00b1, B:44:0x00c8, B:46:0x00cc), top: B:59:0x00ab }] */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00e8  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:30:0x0082 -> B:19:0x0056). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:41:0x00c3 -> B:19:0x0056). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:45:0x00ca -> B:19:0x0056). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:47:0x00d7 -> B:19:0x0056). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:50:0x00e5 -> B:11:0x0027). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r7) {
        /*
            Method dump skipped, instructions count: 254
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.P.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
