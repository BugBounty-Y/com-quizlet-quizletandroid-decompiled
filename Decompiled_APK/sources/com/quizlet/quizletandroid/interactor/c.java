package com.quizlet.quizletandroid.interactor;

import com.google.android.gms.measurement.internal.J;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public List k;
    public int l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ J o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(J j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.o = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        c cVar = new c(this.o, hVar);
        cVar.n = obj;
        return cVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:101:0x02fc, code lost:
    
        if (r4.emit(r0, r18) != r2) goto L112;
     */
    /* JADX WARN: Code restructure failed: missing block: B:109:0x0319, code lost:
    
        if (r4.emit(r0, r18) == r2) goto L110;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:100:0x02e7 A[Catch: Exception -> 0x002f, PHI: r0 r3 r4 r5
  0x02e7: PHI (r0v26 java.util.List) = (r0v25 java.util.List), (r0v51 java.util.List) binds: [B:98:0x02e4, B:14:0x003f] A[DONT_GENERATE, DONT_INLINE]
  0x02e7: PHI (r3v9 int) = (r3v8 int), (r3v13 int) binds: [B:98:0x02e4, B:14:0x003f] A[DONT_GENERATE, DONT_INLINE]
  0x02e7: PHI (r4v10 kotlinx.coroutines.flow.j) = (r4v9 kotlinx.coroutines.flow.j), (r4v38 kotlinx.coroutines.flow.j) binds: [B:98:0x02e4, B:14:0x003f] A[DONT_GENERATE, DONT_INLINE]
  0x02e7: PHI (r5v10 java.lang.Object) = (r5v9 java.lang.Object), (r5v35 java.lang.Object) binds: [B:98:0x02e4, B:14:0x003f] A[DONT_GENERATE, DONT_INLINE], TRY_LEAVE, TryCatch #4 {Exception -> 0x002f, blocks: (B:8:0x002a, B:13:0x003c, B:100:0x02e7, B:16:0x004a, B:93:0x029b, B:94:0x02bd, B:96:0x02c3, B:97:0x02d6, B:19:0x0058, B:83:0x023d), top: B:122:0x0013 }] */
    /* JADX WARN: Removed duplicated region for block: B:111:0x031c  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x0321  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0123 A[Catch: Exception -> 0x00be, LOOP:3: B:47:0x011d->B:49:0x0123, LOOP_END, TryCatch #5 {Exception -> 0x00be, blocks: (B:38:0x00b8, B:46:0x0102, B:47:0x011d, B:49:0x0123, B:50:0x013c), top: B:123:0x00b8 }] */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0164  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x018d A[Catch: Exception -> 0x01a0, LOOP:2: B:55:0x0187->B:57:0x018d, LOOP_END, TryCatch #0 {Exception -> 0x01a0, blocks: (B:54:0x0165, B:55:0x0187, B:57:0x018d, B:59:0x01a3), top: B:116:0x0165 }] */
    /* JADX WARN: Removed duplicated region for block: B:62:0x01b6  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x01c4 A[Catch: Exception -> 0x01df, TRY_LEAVE, TryCatch #1 {Exception -> 0x01df, blocks: (B:63:0x01bc, B:65:0x01c4), top: B:118:0x01bc }] */
    /* JADX WARN: Removed duplicated region for block: B:76:0x021d  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x022a A[Catch: Exception -> 0x006b, TRY_LEAVE, TryCatch #6 {Exception -> 0x006b, blocks: (B:22:0x0064, B:77:0x021f, B:79:0x022a, B:85:0x0240, B:86:0x0258, B:88:0x025e, B:89:0x0271), top: B:125:0x0064 }] */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0240 A[Catch: Exception -> 0x006b, TRY_ENTER, TryCatch #6 {Exception -> 0x006b, blocks: (B:22:0x0064, B:77:0x021f, B:79:0x022a, B:85:0x0240, B:86:0x0258, B:88:0x025e, B:89:0x0271), top: B:125:0x0064 }] */
    /* JADX WARN: Removed duplicated region for block: B:96:0x02c3 A[Catch: Exception -> 0x002f, LOOP:0: B:94:0x02bd->B:96:0x02c3, LOOP_END, TryCatch #4 {Exception -> 0x002f, blocks: (B:8:0x002a, B:13:0x003c, B:100:0x02e7, B:16:0x004a, B:93:0x029b, B:94:0x02bd, B:96:0x02c3, B:97:0x02d6, B:19:0x0058, B:83:0x023d), top: B:122:0x0013 }] */
    /* JADX WARN: Removed duplicated region for block: B:99:0x02e6  */
    /* JADX WARN: Type inference failed for: r0v4, types: [com.quizlet.infra.legacysyncengine.net.c] */
    /* JADX WARN: Type inference failed for: r11v14 */
    /* JADX WARN: Type inference failed for: r11v17, types: [java.lang.Object, kotlinx.coroutines.flow.j] */
    /* JADX WARN: Type inference failed for: r11v20 */
    /* JADX WARN: Type inference failed for: r13v4, types: [com.quizlet.infra.legacysyncengine.net.c] */
    /* JADX WARN: Type inference failed for: r3v0, types: [com.quizlet.infra.legacysyncengine.net.b] */
    /* JADX WARN: Type inference failed for: r3v1 */
    /* JADX WARN: Type inference failed for: r3v10 */
    /* JADX WARN: Type inference failed for: r3v2 */
    /* JADX WARN: Type inference failed for: r4v0, types: [com.quizlet.infra.legacysyncengine.net.b] */
    /* JADX WARN: Type inference failed for: r4v2 */
    /* JADX WARN: Type inference failed for: r4v32 */
    /* JADX WARN: Type inference failed for: r4v5, types: [kotlinx.coroutines.flow.j] */
    /* JADX WARN: Type inference failed for: r5v3 */
    /* JADX WARN: Type inference failed for: r5v36 */
    /* JADX WARN: Type inference failed for: r5v5, types: [java.lang.Object, kotlinx.coroutines.flow.j] */
    /* JADX WARN: Type inference failed for: r6v5, types: [com.quizlet.infra.legacysyncengine.net.c] */
    /* JADX WARN: Type inference failed for: r8v12, types: [com.quizlet.infra.legacysyncengine.net.c] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r19) throws java.lang.Exception {
        /*
            Method dump skipped, instructions count: 828
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.interactor.c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
