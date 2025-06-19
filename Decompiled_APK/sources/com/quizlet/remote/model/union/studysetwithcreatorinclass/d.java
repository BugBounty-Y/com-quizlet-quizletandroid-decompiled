package com.quizlet.remote.model.union.studysetwithcreatorinclass;

import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public List j;
    public List k;
    public e l;
    public int m;
    public final /* synthetic */ e n;
    public final /* synthetic */ i o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public d(e eVar, kotlin.jvm.functions.c cVar, h hVar) {
        super(2, hVar);
        this.n = eVar;
        this.o = (i) cVar;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Path cross not found for [B:16:0x0056, B:21:0x0068], limit reached: 59 */
    /* JADX WARN: Path cross not found for [B:24:0x006e, B:35:0x00ac], limit reached: 59 */
    /* JADX WARN: Path cross not found for [B:37:0x00b2, B:45:0x00e8], limit reached: 59 */
    /* JADX WARN: Path cross not found for [B:48:0x00f2, B:53:0x0104], limit reached: 59 */
    /* JADX WARN: Removed duplicated region for block: B:10:0x0032  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x011b  */
    /* JADX WARN: Type inference failed for: r4v5, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r6v3, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r6v4, types: [java.lang.Object, java.util.Collection] */
    /* JADX WARN: Type inference failed for: r6v5, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r7v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:13:0x0045 -> B:14:0x0047). Please report as a decompilation issue!!! */
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
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.union.studysetwithcreatorinclass.d.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
