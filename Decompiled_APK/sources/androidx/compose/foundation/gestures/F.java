package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class F extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public final /* synthetic */ kotlin.jvm.internal.r A;
    public Object k;
    public Object l;
    public Object m;
    public kotlin.jvm.internal.I n;
    public l1 o;
    public androidx.compose.ui.input.pointer.n p;
    public boolean q;
    public float r;
    public int s;
    public /* synthetic */ Object t;
    public final /* synthetic */ kotlin.jvm.internal.r u;
    public final /* synthetic */ kotlin.jvm.internal.I v;
    public final /* synthetic */ EnumC0320d0 w;
    public final /* synthetic */ kotlin.jvm.internal.r x;
    public final /* synthetic */ Function2 y;
    public final /* synthetic */ Function0 z;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public F(Function0 function0, kotlin.jvm.internal.I i, EnumC0320d0 enumC0320d0, kotlin.jvm.functions.c cVar, Function2 function2, Function0 function02, Function1 function1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.u = (kotlin.jvm.internal.r) function0;
        this.v = i;
        this.w = enumC0320d0;
        this.x = (kotlin.jvm.internal.r) cVar;
        this.y = function2;
        this.z = function02;
        this.A = (kotlin.jvm.internal.r) function1;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r4v0, types: [kotlin.jvm.functions.c, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r7v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        ?? r7 = this.A;
        F f = new F(this.u, this.v, this.w, this.x, this.y, this.z, r7, hVar);
        f.t = obj;
        return f;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((F) create((androidx.compose.ui.input.pointer.z) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:103:0x02aa, code lost:
    
        if (r9.c(r5, r21) == r1) goto L122;
     */
    /* JADX WARN: Code restructure failed: missing block: B:121:0x0323, code lost:
    
        if (r9 == r1) goto L122;
     */
    /* JADX WARN: Code restructure failed: missing block: B:155:0x03a2, code lost:
    
        if ((r4 != null ? r4 == androidx.compose.foundation.gestures.EnumC0320d0.a ? androidx.compose.ui.geometry.b.e(r9) : androidx.compose.ui.geometry.b.d(r9) : androidx.compose.ui.geometry.b.c(r9)) == com.skydoves.balloon.internals.DefinitionKt.NO_Float_VALUE) goto L120;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x00e6, code lost:
    
        if (r10 == r1) goto L122;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:109:0x02ba  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x02d4  */
    /* JADX WARN: Removed duplicated region for block: B:166:0x03ba  */
    /* JADX WARN: Removed duplicated region for block: B:167:0x03c0  */
    /* JADX WARN: Removed duplicated region for block: B:176:0x017b A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x00fe  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x010a  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x014a A[PHI: r2 r3 r4 r5 r7 r8 r9 r10 r11 r12 r14
  0x014a: PHI (r2v20 float) = (r2v21 float), (r2v35 float) binds: [B:39:0x0146, B:13:0x0071] A[DONT_GENERATE, DONT_INLINE]
  0x014a: PHI (r3v9 kotlin.jvm.internal.I) = (r3v61 kotlin.jvm.internal.I), (r3v0 kotlin.jvm.internal.I) binds: [B:39:0x0146, B:13:0x0071] A[DONT_GENERATE, DONT_INLINE]
  0x014a: PHI (r4v5 androidx.compose.ui.input.pointer.g) = (r4v11 androidx.compose.ui.input.pointer.g), (r4v0 androidx.compose.ui.input.pointer.g) binds: [B:39:0x0146, B:13:0x0071] A[DONT_GENERATE, DONT_INLINE]
  0x014a: PHI (r5v4 java.lang.Object) = (r5v20 java.lang.Object), (r5v35 java.lang.Object) binds: [B:39:0x0146, B:13:0x0071] A[DONT_GENERATE, DONT_INLINE]
  0x014a: PHI (r7v4 androidx.compose.foundation.gestures.d0) = (r7v9 androidx.compose.foundation.gestures.d0), (r7v0 androidx.compose.foundation.gestures.d0) binds: [B:39:0x0146, B:13:0x0071] A[DONT_GENERATE, DONT_INLINE]
  0x014a: PHI (r8v12 kotlin.jvm.internal.I) = (r8v14 kotlin.jvm.internal.I), (r8v24 kotlin.jvm.internal.I) binds: [B:39:0x0146, B:13:0x0071] A[DONT_GENERATE, DONT_INLINE]
  0x014a: PHI (r9v7 androidx.compose.ui.input.pointer.z) = (r9v10 androidx.compose.ui.input.pointer.z), (r9v31 androidx.compose.ui.input.pointer.z) binds: [B:39:0x0146, B:13:0x0071] A[DONT_GENERATE, DONT_INLINE]
  0x014a: PHI (r10v11 androidx.compose.ui.input.pointer.z) = (r10v14 androidx.compose.ui.input.pointer.z), (r10v29 androidx.compose.ui.input.pointer.z) binds: [B:39:0x0146, B:13:0x0071] A[DONT_GENERATE, DONT_INLINE]
  0x014a: PHI (r11v7 androidx.compose.ui.input.pointer.n) = (r11v8 androidx.compose.ui.input.pointer.n), (r11v21 androidx.compose.ui.input.pointer.n) binds: [B:39:0x0146, B:13:0x0071] A[DONT_GENERATE, DONT_INLINE]
  0x014a: PHI (r12v3 androidx.compose.foundation.gestures.l1) = (r12v4 androidx.compose.foundation.gestures.l1), (r12v15 androidx.compose.foundation.gestures.l1) binds: [B:39:0x0146, B:13:0x0071] A[DONT_GENERATE, DONT_INLINE]
  0x014a: PHI (r14v3 kotlin.jvm.internal.I) = (r14v4 kotlin.jvm.internal.I), (r14v15 kotlin.jvm.internal.I) binds: [B:39:0x0146, B:13:0x0071] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0155  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0197  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x01bd  */
    /* JADX WARN: Type inference failed for: r10v18, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r13v5 */
    /* JADX WARN: Type inference failed for: r13v6 */
    /* JADX WARN: Type inference failed for: r13v7, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r15v0, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r16v1, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r1v2, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r2v4, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r3v2, types: [kotlin.jvm.functions.c, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r3v55, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r6v27, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:100:0x0280 -> B:101:0x0284). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:103:0x02aa -> B:105:0x02ae). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:121:0x0323 -> B:123:0x0326). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:30:0x00fe -> B:31:0x0104). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:66:0x01b5 -> B:101:0x0284). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r22) {
        /*
            Method dump skipped, instructions count: 993
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.F.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
