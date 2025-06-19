package com.quizlet.data.repository.folderwithcreator;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes2.dex */
public final class c extends i implements Function2 {
    public Object j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ e m;
    public final /* synthetic */ long n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(e eVar, long j, h hVar) {
        super(2, hVar);
        this.m = eVar;
        this.n = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        c cVar = new c(this.m, this.n, hVar);
        cVar.l = obj;
        return cVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((InterfaceC5002j) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:69:0x011c, code lost:
    
        if (com.google.android.gms.internal.mlkit_vision_camera.I1.a(r1, r14) == r0) goto L70;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:40:0x009e A[Catch: Exception -> 0x0065, TRY_LEAVE, TryCatch #3 {Exception -> 0x0065, blocks: (B:29:0x0061, B:38:0x008f, B:40:0x009e), top: B:82:0x0061 }] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00af  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00cf  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00e1  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00e2  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00fb A[Catch: Exception -> 0x0027, TRY_ENTER, TRY_LEAVE, TryCatch #2 {Exception -> 0x0027, blocks: (B:9:0x0022, B:68:0x00fb), top: B:80:0x0016 }] */
    /* JADX WARN: Type inference failed for: r3v0, types: [long] */
    /* JADX WARN: Type inference failed for: r3v1 */
    /* JADX WARN: Type inference failed for: r3v12 */
    /* JADX WARN: Type inference failed for: r3v13 */
    /* JADX WARN: Type inference failed for: r3v2 */
    /* JADX WARN: Type inference failed for: r3v3 */
    /* JADX WARN: Type inference failed for: r3v7 */
    /* JADX WARN: Type inference failed for: r8v9, types: [com.quizlet.remote.model.union.folderwithcreator.e] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r15) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 296
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folderwithcreator.c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
