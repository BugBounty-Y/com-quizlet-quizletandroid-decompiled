package io.ktor.client.call;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.U;
import kotlinx.coroutines.C;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public class b implements C {
    public static final /* synthetic */ AtomicIntegerFieldUpdater d;
    public static final io.ktor.util.a e;
    public final io.ktor.client.c a;
    public io.ktor.client.request.b b;
    public io.ktor.client.statement.b c;

    @NotNull
    private volatile /* synthetic */ int received;

    static {
        U uC;
        C4950i c4950iA = K.a(Object.class);
        try {
            uC = K.c(Object.class);
        } catch (Throwable unused) {
            uC = null;
        }
        e = new io.ktor.util.a("CustomResponse", new io.ktor.util.reflect.a(c4950iA, uC));
        d = AtomicIntegerFieldUpdater.newUpdater(b.class, "received");
    }

    public b(io.ktor.client.c client) {
        Intrinsics.checkNotNullParameter(client, "client");
        this.a = client;
        this.received = 0;
    }

    /* JADX WARN: Code restructure failed: missing block: B:43:0x00be, code lost:
    
        if (r10 == r1) goto L48;
     */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00e5  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00e9 A[Catch: all -> 0x0033, TryCatch #0 {all -> 0x0033, blocks: (B:13:0x002e, B:50:0x00d9, B:55:0x00e9, B:58:0x00fc, B:59:0x010f), top: B:63:0x002e }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(io.ktor.util.reflect.a r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            Method dump skipped, instructions count: 287
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.call.b.a(io.ktor.util.reflect.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public boolean b() {
        return false;
    }

    public final io.ktor.client.request.b c() {
        io.ktor.client.request.b bVar = this.b;
        if (bVar != null) {
            return bVar;
        }
        Intrinsics.m("request");
        throw null;
    }

    public final io.ktor.client.statement.b d() {
        io.ktor.client.statement.b bVar = this.c;
        if (bVar != null) {
            return bVar;
        }
        Intrinsics.m("response");
        throw null;
    }

    public Object e() {
        return d().c();
    }

    public final io.ktor.util.e f() {
        return c().f();
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return d().getCoroutineContext();
    }

    public final String toString() {
        return "HttpClientCall[" + c().i() + ", " + d().g() + ']';
    }
}
