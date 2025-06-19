package io.ktor.client.plugins;

import kotlin.Unit;

/* loaded from: classes3.dex */
public final class c0 extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;
    public int k;
    public /* synthetic */ io.ktor.util.pipeline.e l;
    public final /* synthetic */ kotlin.jvm.functions.c m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c0(kotlin.jvm.functions.c cVar, kotlin.coroutines.h hVar, int i) {
        super(3, hVar);
        this.j = i;
        this.m = cVar;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        io.ktor.util.pipeline.e eVar = (io.ktor.util.pipeline.e) obj;
        switch (this.j) {
            case 0:
                c0 c0Var = new c0(this.m, (kotlin.coroutines.h) obj3, 0);
                c0Var.l = eVar;
                return c0Var.invokeSuspend(Unit.a);
            case 1:
                c0 c0Var2 = new c0(this.m, (kotlin.coroutines.h) obj3, 1);
                c0Var2.l = eVar;
                return c0Var2.invokeSuspend(Unit.a);
            default:
                c0 c0Var3 = new c0(this.m, (kotlin.coroutines.h) obj3, 2);
                c0Var3.l = eVar;
                return c0Var3.invokeSuspend(Unit.a);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:40:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00d8  */
    /* JADX WARN: Removed duplicated region for block: B:77:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:79:? A[RETURN, SYNTHETIC] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r14) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 226
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.c0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
