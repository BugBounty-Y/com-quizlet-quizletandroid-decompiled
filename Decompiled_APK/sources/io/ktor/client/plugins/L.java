package io.ktor.client.plugins;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class L extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public kotlin.jvm.functions.c j;
    public kotlin.jvm.functions.c k;
    public Function2 l;
    public Function2 m;
    public Object n;
    public int o;
    public int p;
    public int q;
    public /* synthetic */ io.ktor.client.plugins.api.g r;
    public /* synthetic */ io.ktor.client.request.c s;
    public final /* synthetic */ com.perimeterx.mobile_sdk.api_data.h t;
    public final /* synthetic */ kotlin.jvm.functions.c u;
    public final /* synthetic */ int v;
    public final /* synthetic */ com.quizlet.features.questiontypes.written.ui.f w;
    public final /* synthetic */ Function2 x;
    public final /* synthetic */ io.ktor.client.plugins.api.c y;
    public final /* synthetic */ I z;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(com.perimeterx.mobile_sdk.api_data.h hVar, kotlin.jvm.functions.c cVar, int i, com.quizlet.features.questiontypes.written.ui.f fVar, Function2 function2, io.ktor.client.plugins.api.c cVar2, I i2, kotlin.coroutines.h hVar2) {
        super(3, hVar2);
        this.t = hVar;
        this.u = cVar;
        this.v = i;
        this.w = fVar;
        this.x = function2;
        this.y = cVar2;
        this.z = i2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        io.ktor.client.plugins.api.c cVar = this.y;
        I i = this.z;
        L l = new L(this.t, this.u, this.v, this.w, this.x, cVar, i, (kotlin.coroutines.h) obj3);
        l.r = (io.ktor.client.plugins.api.g) obj;
        l.s = (io.ktor.client.request.c) obj2;
        return l.invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x00c7 A[Catch: all -> 0x0057, TRY_ENTER, TryCatch #0 {all -> 0x0057, blocks: (B:34:0x00c7, B:35:0x00d4, B:38:0x00f2, B:40:0x00f8, B:42:0x0111, B:11:0x0050), top: B:57:0x0050 }] */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00f0  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00f8 A[Catch: all -> 0x0057, TryCatch #0 {all -> 0x0057, blocks: (B:34:0x00c7, B:35:0x00d4, B:38:0x00f2, B:40:0x00f8, B:42:0x0111, B:11:0x0050), top: B:57:0x0050 }] */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0180  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:54:0x0180 -> B:7:0x002b). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r17) {
        /*
            Method dump skipped, instructions count: 426
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.L.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
