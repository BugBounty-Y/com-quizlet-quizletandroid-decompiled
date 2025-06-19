package com.perimeterx.mobile_sdk.detections.device.motion_interception;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.channels.w;

/* loaded from: classes2.dex */
public final class b extends i implements Function2 {
    public final /* synthetic */ int j;
    public w k;
    public kotlinx.coroutines.channels.c l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(int i, int i2, h hVar) {
        super(i, hVar);
        this.j = i2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        switch (this.j) {
            case 0:
                return new b(2, 0, hVar);
            default:
                return new b(2, 1, hVar);
        }
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        h hVar = (h) obj2;
        switch (this.j) {
            case 0:
                return new b(2, 0, hVar).invokeSuspend(Unit.a);
            default:
                return new b(2, 1, hVar).invokeSuspend(Unit.a);
        }
    }

    /*  JADX ERROR: JadxRuntimeException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Can't find top splitter block for handler:B:77:0x009d
        	at jadx.core.utils.BlockUtils.getTopSplitterForHandler(BlockUtils.java:1178)
        	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.collectHandlerRegions(ExcHandlersRegionMaker.java:53)
        	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.process(ExcHandlersRegionMaker.java:38)
        	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:27)
        */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:24:0x004b A[Catch: all -> 0x0060, TryCatch #0 {all -> 0x0060, blocks: (B:9:0x0018, B:19:0x0036, B:22:0x0043, B:24:0x004b, B:29:0x0062, B:14:0x0026, B:18:0x0031), top: B:78:0x000e }] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0062 A[Catch: all -> 0x0060, TRY_LEAVE, TryCatch #0 {all -> 0x0060, blocks: (B:9:0x0018, B:19:0x0036, B:22:0x0043, B:24:0x004b, B:29:0x0062, B:14:0x0026, B:18:0x0031), top: B:78:0x000e }] */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00b2 A[Catch: all -> 0x00ca, TRY_LEAVE, TryCatch #3 {all -> 0x00ca, blocks: (B:42:0x007f, B:52:0x009d, B:55:0x00aa, B:57:0x00b2, B:58:0x00b8, B:60:0x00c1, B:66:0x00dc, B:63:0x00cc, B:65:0x00d4, B:69:0x00f7, B:47:0x008d, B:51:0x0098), top: B:84:0x0075 }] */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00f7 A[Catch: all -> 0x00ca, TRY_ENTER, TRY_LEAVE, TryCatch #3 {all -> 0x00ca, blocks: (B:42:0x007f, B:52:0x009d, B:55:0x00aa, B:57:0x00b2, B:58:0x00b8, B:60:0x00c1, B:66:0x00dc, B:63:0x00cc, B:65:0x00d4, B:69:0x00f7, B:47:0x008d, B:51:0x0098), top: B:84:0x0075 }] */
    /* JADX WARN: Type inference failed for: r5v0, types: [int] */
    /* JADX WARN: Type inference failed for: r5v1, types: [kotlinx.coroutines.channels.w] */
    /* JADX WARN: Type inference failed for: r5v10, types: [kotlinx.coroutines.channels.w] */
    /* JADX WARN: Type inference failed for: r5v13, types: [kotlinx.coroutines.channels.w] */
    /* JADX WARN: Type inference failed for: r5v17 */
    /* JADX WARN: Type inference failed for: r5v18 */
    /* JADX WARN: Type inference failed for: r5v19 */
    /* JADX WARN: Type inference failed for: r5v2, types: [kotlinx.coroutines.channels.h] */
    /* JADX WARN: Type inference failed for: r5v20 */
    /* JADX WARN: Type inference failed for: r5v3, types: [kotlinx.coroutines.channels.w] */
    /* JADX WARN: Type inference failed for: r5v4, types: [kotlinx.coroutines.channels.w] */
    /* JADX WARN: Type inference failed for: r5v6, types: [kotlinx.coroutines.channels.w] */
    /* JADX WARN: Type inference failed for: r5v7, types: [int] */
    /* JADX WARN: Type inference failed for: r5v8, types: [kotlinx.coroutines.channels.w] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:25:0x005d -> B:19:0x0036). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:67:0x00f4 -> B:52:0x009d). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            Method dump skipped, instructions count: 268
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.detections.device.motion_interception.b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
