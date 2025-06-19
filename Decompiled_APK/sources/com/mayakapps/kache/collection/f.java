package com.mayakapps.kache.collection;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.sequences.i;

/* loaded from: classes2.dex */
public final class f extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public Object[] k;
    public Object l;
    public int m;
    public int n;
    public int o;
    public int p;
    public long q;
    public int r;
    public /* synthetic */ Object s;
    public final /* synthetic */ d t;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(d dVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.t = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        f fVar = new f(this.t, hVar);
        fVar.s = obj;
        return fVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((i) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x00b2  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00c6  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x00ef  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00f8  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:25:0x00b0 -> B:35:0x00f6). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:26:0x00b2 -> B:27:0x00c4). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:29:0x00cd -> B:32:0x00ec). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r22) {
        /*
            Method dump skipped, instructions count: 253
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.collection.f.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
