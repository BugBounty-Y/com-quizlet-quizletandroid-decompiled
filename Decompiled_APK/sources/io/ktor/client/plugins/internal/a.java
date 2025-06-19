package io.ktor.client.plugins.internal;

import io.ktor.utils.io.B;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public kotlinx.io.a j;
    public kotlinx.io.i k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ d n;
    public final /* synthetic */ b o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(d dVar, b bVar, h hVar) {
        super(2, hVar);
        this.n = dVar;
        this.o = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        a aVar = new a(this.n, this.o, hVar);
        aVar.m = obj;
        return aVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((B) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /*  JADX ERROR: JadxRuntimeException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Can't find top splitter block for handler:B:57:0x00f0
        	at jadx.core.utils.BlockUtils.getTopSplitterForHandler(BlockUtils.java:1178)
        	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.collectHandlerRegions(ExcHandlersRegionMaker.java:53)
        	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.process(ExcHandlersRegionMaker.java:38)
        	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:27)
        */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Not initialized variable reg: 10, insn: 0x0118: INVOKE (r10 I:java.lang.Object) VIRTUAL call: java.lang.Object.getClass():java.lang.Class A[MD:():java.lang.Class<?> (c)], block:B:55:0x0118 */
    /* JADX WARN: Path cross not found for [B:30:0x007b, B:33:0x008a], limit reached: 57 */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0047 A[PHI: r1 r10 r15
  0x0047: PHI (r1v2 io.ktor.utils.io.B) = (r1v5 io.ktor.utils.io.B), (r1v14 io.ktor.utils.io.B) binds: [B:34:0x00a6, B:19:0x0044] A[DONT_GENERATE, DONT_INLINE]
  0x0047: PHI (r10v2 ??) = (r10v15 ??), (r10v16 ??) binds: [B:34:0x00a6, B:19:0x0044] A[DONT_GENERATE, DONT_INLINE]
  0x0047: PHI (r15v5 java.lang.Object) = (r15v15 java.lang.Object), (r15v0 java.lang.Object) binds: [B:34:0x00a6, B:19:0x0044] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:28:0x006b A[Catch: all -> 0x0026, TRY_ENTER, TryCatch #1 {all -> 0x0026, blocks: (B:9:0x0021, B:48:0x00f0, B:25:0x0061, B:28:0x006b, B:30:0x007b, B:33:0x008a, B:36:0x00a9, B:37:0x00ac, B:39:0x00b6, B:45:0x00dd, B:42:0x00d8, B:49:0x00fe, B:51:0x0104, B:54:0x0117, B:16:0x0039, B:19:0x0044, B:22:0x004f), top: B:58:0x000f }] */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00a8  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00b6 A[Catch: all -> 0x0026, Exception -> 0x00f0, TryCatch #0 {Exception -> 0x00f0, blocks: (B:9:0x0021, B:37:0x00ac, B:39:0x00b6, B:45:0x00dd, B:42:0x00d8, B:16:0x0039), top: B:58:0x000f }] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00fe A[Catch: all -> 0x0026, TryCatch #1 {all -> 0x0026, blocks: (B:9:0x0021, B:48:0x00f0, B:25:0x0061, B:28:0x006b, B:30:0x007b, B:33:0x008a, B:36:0x00a9, B:37:0x00ac, B:39:0x00b6, B:45:0x00dd, B:42:0x00d8, B:49:0x00fe, B:51:0x0104, B:54:0x0117, B:16:0x0039, B:19:0x0044, B:22:0x004f), top: B:58:0x000f }] */
    /* JADX WARN: Type inference failed for: r10v1, types: [kotlinx.io.a] */
    /* JADX WARN: Type inference failed for: r10v10, types: [kotlinx.io.a] */
    /* JADX WARN: Type inference failed for: r10v15 */
    /* JADX WARN: Type inference failed for: r10v16 */
    /* JADX WARN: Type inference failed for: r10v2, types: [kotlinx.io.a] */
    /* JADX WARN: Type inference failed for: r10v5, types: [java.lang.Object, kotlinx.io.a] */
    /* JADX WARN: Type inference failed for: r10v9, types: [kotlinx.io.a] */
    /* JADX WARN: Type inference failed for: r1v0, types: [int] */
    /* JADX WARN: Type inference failed for: r1v1, types: [kotlinx.io.i] */
    /* JADX WARN: Type inference failed for: r1v15, types: [kotlinx.io.i] */
    /* JADX WARN: Type inference failed for: r1v16, types: [kotlinx.io.i] */
    /* JADX WARN: Type inference failed for: r1v4, types: [kotlinx.io.i] */
    /* JADX WARN: Type inference failed for: r1v7, types: [java.lang.Object, kotlinx.io.d] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:38:0x00b4 -> B:48:0x00f0). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:46:0x00ed -> B:48:0x00f0). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r15) {
        /*
            Method dump skipped, instructions count: 289
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.internal.a.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
