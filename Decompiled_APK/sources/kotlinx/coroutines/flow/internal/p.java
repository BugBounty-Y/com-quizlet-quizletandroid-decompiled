package kotlinx.coroutines.flow.internal;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class p extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.channels.l j;
    public byte[] k;
    public int l;
    public int m;
    public int n;
    public /* synthetic */ Object o;
    public final /* synthetic */ InterfaceC4992i[] p;
    public final /* synthetic */ Function0 q;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i r;
    public final /* synthetic */ InterfaceC5002j s;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public p(kotlin.coroutines.h hVar, Function0 function0, kotlin.jvm.functions.c cVar, InterfaceC5002j interfaceC5002j, InterfaceC4992i[] interfaceC4992iArr) {
        super(2, hVar);
        this.p = interfaceC4992iArr;
        this.q = function0;
        this.r = (kotlin.coroutines.jvm.internal.i) cVar;
        this.s = interfaceC5002j;
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        ?? r3 = this.r;
        p pVar = new p(hVar, this.q, r3, this.s, this.p);
        pVar.o = obj;
        return pVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((p) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:43:0x0085, code lost:
    
        if (r8 != 0) goto L20;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Path cross not found for [B:34:0x00c4, B:32:0x00b5], limit reached: 44 */
    /* JADX WARN: Path cross not found for [B:35:0x00c6, B:20:0x0085], limit reached: 44 */
    /* JADX WARN: Path cross not found for [B:37:0x00d4, B:40:0x00e7], limit reached: 44 */
    /* JADX WARN: Removed duplicated region for block: B:25:0x00a2  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x00a5 A[LOOP:0: B:27:0x00a5->B:45:?, LOOP_START, PHI: r8 r12
  0x00a5: PHI (r8v3 int) = (r8v2 int), (r8v4 int) binds: [B:24:0x00a0, B:45:?] A[DONT_GENERATE, DONT_INLINE]
  0x00a5: PHI (r12v4 kotlin.collections.IndexedValue) = (r12v3 kotlin.collections.IndexedValue), (r12v10 kotlin.collections.IndexedValue) binds: [B:24:0x00a0, B:45:?] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Type inference failed for: r13v2, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    /* JADX WARN: Type inference failed for: r2v6, types: [int] */
    /* JADX WARN: Type inference failed for: r2v8, types: [int] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:38:0x00e4 -> B:20:0x0085). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:41:0x00fc -> B:20:0x0085). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r20) {
        /*
            Method dump skipped, instructions count: 255
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.internal.p.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
