package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class h1 extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public Object k;
    public Object l;
    public kotlin.jvm.internal.J m;
    public long n;
    public int o;
    public /* synthetic */ Object p;
    public final /* synthetic */ kotlinx.coroutines.C q;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i r;
    public final /* synthetic */ Function1 s;
    public final /* synthetic */ Function1 t;
    public final /* synthetic */ C0326g0 u;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public h1(kotlinx.coroutines.C c, kotlin.jvm.functions.c cVar, Function1 function1, androidx.compose.foundation.H h, Function1 function12, C0326g0 c0326g0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.q = c;
        this.r = (kotlin.coroutines.jvm.internal.i) cVar;
        this.s = function1;
        this.t = function12;
        this.u = c0326g0;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0326g0 c0326g0 = this.u;
        h1 h1Var = new h1(this.q, this.r, this.s, null, this.t, c0326g0, hVar);
        h1Var.p = obj;
        return h1Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h1) create((androidx.compose.ui.input.pointer.z) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x008b, code lost:
    
        if (r2.f(r4, r4, r18) == r1) goto L64;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x00bf, code lost:
    
        if (androidx.compose.foundation.gestures.k1.a(r4, r18) == r1) goto L64;
     */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00a7  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0130  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x013a  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0143  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0167  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0170 A[Catch: PointerEventTimeoutCancellationException -> 0x018e, TryCatch #5 {PointerEventTimeoutCancellationException -> 0x018e, blocks: (B:54:0x016a, B:56:0x0170, B:57:0x017b), top: B:87:0x016a }] */
    /* JADX WARN: Removed duplicated region for block: B:57:0x017b A[Catch: PointerEventTimeoutCancellationException -> 0x018e, TRY_LEAVE, TryCatch #5 {PointerEventTimeoutCancellationException -> 0x018e, blocks: (B:54:0x016a, B:56:0x0170, B:57:0x017b), top: B:87:0x016a }] */
    /* JADX WARN: Removed duplicated region for block: B:61:0x0190  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x01af  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x01bd A[ADDED_TO_REGION] */
    /* JADX WARN: Type inference failed for: r2v29 */
    /* JADX WARN: Type inference failed for: r2v33, types: [kotlin.coroutines.CoroutineContext, kotlin.coroutines.h, kotlinx.coroutines.D] */
    /* JADX WARN: Type inference failed for: r2v34 */
    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    /* JADX WARN: Type inference failed for: r5v13, types: [kotlin.coroutines.CoroutineContext, kotlin.coroutines.h, kotlinx.coroutines.D] */
    /* JADX WARN: Type inference failed for: r5v14 */
    /* JADX WARN: Type inference failed for: r5v6 */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r19) {
        /*
            Method dump skipped, instructions count: 480
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.h1.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
