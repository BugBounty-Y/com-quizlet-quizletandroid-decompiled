package io.ktor.util.pipeline;

import java.util.List;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends e {
    public final List b;
    public final CoroutineContext c;
    public Object d;
    public int e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(Object context, List interceptors, Object subject, CoroutineContext coroutineContext) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(interceptors, "interceptors");
        Intrinsics.checkNotNullParameter(subject, "subject");
        Intrinsics.checkNotNullParameter(coroutineContext, "coroutineContext");
        this.b = interceptors;
        this.c = coroutineContext;
        this.d = subject;
    }

    @Override // io.ktor.util.pipeline.e
    public final Object a(Object obj, kotlin.coroutines.jvm.internal.c cVar) {
        this.e = 0;
        Intrinsics.checkNotNullParameter(obj, "<set-?>");
        this.d = obj;
        return c(cVar);
    }

    @Override // io.ktor.util.pipeline.e
    public final Object b() {
        return this.d;
    }

    @Override // io.ktor.util.pipeline.e
    public final Object c(kotlin.coroutines.h hVar) {
        int i = this.e;
        if (i < 0) {
            return this.d;
        }
        if (i < this.b.size()) {
            return e(hVar);
        }
        this.e = -1;
        return this.d;
    }

    @Override // io.ktor.util.pipeline.e
    public final Object d(Object obj, kotlin.coroutines.h hVar) {
        Intrinsics.checkNotNullParameter(obj, "<set-?>");
        this.d = obj;
        return c(hVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object e(kotlin.coroutines.h r8) {
        /*
            r7 = this;
            boolean r0 = r8 instanceof io.ktor.util.pipeline.a
            if (r0 == 0) goto L13
            r0 = r8
            io.ktor.util.pipeline.a r0 = (io.ktor.util.pipeline.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            io.ktor.util.pipeline.a r0 = new io.ktor.util.pipeline.a
            r0.<init>(r7, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            io.ktor.util.pipeline.b r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L35
        L29:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r2 = r7
        L35:
            int r8 = r2.e
            r4 = -1
            if (r8 != r4) goto L3b
            goto L45
        L3b:
            java.util.List r5 = r2.b
            int r6 = r5.size()
            if (r8 < r6) goto L48
            r2.e = r4
        L45:
            java.lang.Object r8 = r2.d
            return r8
        L48:
            java.lang.Object r4 = r5.get(r8)
            kotlin.jvm.functions.c r4 = (kotlin.jvm.functions.c) r4
            int r8 = r8 + 1
            r2.e = r8
            java.lang.Object r8 = r2.d
            r0.j = r2
            r0.m = r3
            java.lang.Object r8 = r4.invoke(r2, r8, r0)
            if (r8 != r1) goto L35
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.util.pipeline.b.e(kotlin.coroutines.h):java.lang.Object");
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.c;
    }
}
