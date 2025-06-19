package io.ktor.client.plugins;

import java.nio.charset.Charset;
import kotlin.Unit;

/* renamed from: io.ktor.client.plugins.z, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4878z extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public /* synthetic */ io.ktor.client.request.c j;
    public /* synthetic */ Object k;
    public final /* synthetic */ String l;
    public final /* synthetic */ Charset m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4878z(String str, Charset charset, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.l = str;
        this.m = charset;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        C4878z c4878z = new C4878z(this.l, this.m, (kotlin.coroutines.h) obj3);
        c4878z.j = (io.ktor.client.request.c) obj;
        c4878z.k = obj2;
        return c4878z.invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x00ff  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            Method dump skipped, instructions count: 282
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.C4878z.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
