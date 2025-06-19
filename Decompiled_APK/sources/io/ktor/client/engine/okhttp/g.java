package io.ktor.client.engine.okhttp;

import io.ktor.utils.io.B;
import java.io.Closeable;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.H;
import okio.InterfaceC5093j;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Closeable j;
    public CoroutineContext k;
    public io.ktor.client.request.d l;
    public InterfaceC5093j m;
    public H n;
    public int o;
    public /* synthetic */ Object p;
    public final /* synthetic */ InterfaceC5093j q;
    public final /* synthetic */ CoroutineContext r;
    public final /* synthetic */ io.ktor.client.request.d s;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(InterfaceC5093j interfaceC5093j, CoroutineContext coroutineContext, io.ktor.client.request.d dVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.q = interfaceC5093j;
        this.r = coroutineContext;
        this.s = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        g gVar = new g(this.q, this.r, this.s, hVar);
        gVar.p = obj;
        return gVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((B) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x00a5, code lost:
    
        if (((io.ktor.utils.io.k) r12).g(r11) != r0) goto L8;
     */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00b8  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00c6  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00b1 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:30:0x00a5 -> B:8:0x001d). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r12) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 202
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.engine.okhttp.g.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
