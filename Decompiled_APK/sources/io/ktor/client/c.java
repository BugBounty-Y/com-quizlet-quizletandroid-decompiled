package io.ktor.client;

import androidx.compose.material.C0574q;
import androidx.paging.C1319i;
import com.quizlet.quizletandroid.ui.setcreation.managers.n;
import io.ktor.client.engine.okhttp.f;
import io.ktor.client.plugins.AbstractC4857d;
import io.ktor.client.plugins.AbstractC4859f;
import io.ktor.client.plugins.AbstractC4866m;
import io.ktor.client.plugins.AbstractC4873u;
import io.ktor.client.plugins.AbstractC4875w;
import io.ktor.client.plugins.G;
import io.ktor.client.plugins.H;
import io.ktor.client.plugins.W;
import io.ktor.client.request.h;
import io.ktor.client.statement.e;
import java.io.Closeable;
import java.io.IOException;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.InterfaceC5025j0;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class c implements C, Closeable, AutoCloseable {
    public static final /* synthetic */ AtomicIntegerFieldUpdater l = AtomicIntegerFieldUpdater.newUpdater(c.class, "closed");
    public final f a;
    public final boolean b;
    public final C5027k0 c;

    @NotNull
    private volatile /* synthetic */ int closed;
    public final CoroutineContext d;
    public final io.ktor.client.request.f e;
    public final e f;
    public final h g;
    public final io.ktor.client.statement.a h;
    public final io.ktor.util.e i;
    public final n j;
    public final d k;

    public c(f engine, d other) {
        int i = 1;
        int i2 = 7;
        int i3 = 3;
        Intrinsics.checkNotNullParameter(engine, "engine");
        Intrinsics.checkNotNullParameter(other, "userConfig");
        Intrinsics.checkNotNullParameter(engine, "engine");
        Intrinsics.checkNotNullParameter(other, "userConfig");
        this.a = engine;
        this.closed = 0;
        C5027k0 c5027k0 = new C5027k0((InterfaceC5025j0) engine.g.get(C5023i0.a));
        this.c = c5027k0;
        this.d = engine.g.plus(c5027k0);
        this.e = new io.ktor.client.request.f();
        this.f = new e();
        h hVar = new h();
        this.g = hVar;
        this.h = new io.ktor.client.statement.a();
        this.i = new io.ktor.util.e();
        this.j = new n(10);
        d dVar = new d();
        this.k = dVar;
        if (this.b) {
            c5027k0.Q(new a(this));
        }
        Intrinsics.checkNotNullParameter(this, "client");
        kotlin.coroutines.h hVar2 = null;
        hVar.f(h.i, new io.ktor.client.engine.c(this, engine, null));
        hVar.f(h.j, new C1319i(this, hVar2, i2));
        dVar.a(H.b, new com.sdk.growthbook.utils.a(i3));
        dVar.a(AbstractC4857d.c, new com.sdk.growthbook.utils.a(i3));
        dVar.a(AbstractC4866m.c, new com.sdk.growthbook.utils.a(i3));
        if (other.f) {
            com.sdk.growthbook.utils.a block = new com.sdk.growthbook.utils.a(i);
            Intrinsics.checkNotNullParameter("DefaultTransformers", "key");
            Intrinsics.checkNotNullParameter(block, "block");
            dVar.c.put("DefaultTransformers", block);
        }
        dVar.a(W.c, new com.sdk.growthbook.utils.a(i3));
        io.ktor.client.plugins.api.d dVar2 = AbstractC4873u.b;
        dVar.a(dVar2, new com.sdk.growthbook.utils.a(i3));
        if (other.e) {
            dVar.a(G.d, new com.sdk.growthbook.utils.a(i3));
        }
        Intrinsics.checkNotNullParameter(other, "other");
        dVar.e = other.e;
        dVar.f = other.f;
        dVar.a.putAll(other.a);
        dVar.b.putAll(other.b);
        dVar.c.putAll(other.c);
        if (other.f) {
            dVar.a(io.ktor.client.plugins.C.b, new com.sdk.growthbook.utils.a(i3));
        }
        io.ktor.util.a aVar = AbstractC4859f.a;
        Intrinsics.checkNotNullParameter(dVar, "<this>");
        com.sdk.growthbook.utils.a block2 = new com.sdk.growthbook.utils.a(dVar);
        Intrinsics.checkNotNullParameter(dVar, "<this>");
        Intrinsics.checkNotNullParameter(block2, "block");
        dVar.a(dVar2, block2);
        Intrinsics.checkNotNullParameter(this, "client");
        Iterator it2 = dVar.a.values().iterator();
        while (it2.hasNext()) {
            ((Function1) it2.next()).invoke(this);
        }
        Iterator it3 = dVar.c.values().iterator();
        while (it3.hasNext()) {
            ((Function1) it3.next()).invoke(this);
        }
        this.f.f(e.f, new C0574q(this, hVar2, i2));
        this.b = true;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(io.ktor.client.request.c r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof io.ktor.client.b
            if (r0 == 0) goto L13
            r0 = r6
            io.ktor.client.b r0 = (io.ktor.client.b) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            io.ktor.client.b r0 = new io.ktor.client.b
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L46
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.quizletandroid.ui.login.di.a r6 = io.ktor.client.utils.a.a
            com.quizlet.quizletandroid.ui.setcreation.managers.n r2 = r4.j
            r2.i(r6)
            java.lang.Object r6 = r5.d
            r0.l = r3
            io.ktor.client.request.f r2 = r4.e
            java.lang.Object r6 = r2.a(r5, r6, r0)
            if (r6 != r1) goto L46
            return r1
        L46:
            java.lang.String r5 = "null cannot be cast to non-null type io.ktor.client.call.HttpClientCall"
            kotlin.jvm.internal.Intrinsics.e(r6, r5)
            io.ktor.client.call.b r6 = (io.ktor.client.call.b) r6
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.c.a(io.ktor.client.request.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        if (l.compareAndSet(this, 0, 1)) {
            io.ktor.util.e eVar = (io.ktor.util.e) this.i.b(AbstractC4875w.a);
            for (io.ktor.util.a aVar : CollectionsKt.w0(eVar.c().keySet())) {
                Intrinsics.e(aVar, "null cannot be cast to non-null type io.ktor.util.AttributeKey<kotlin.Any>");
                Object objB = eVar.b(aVar);
                if (objB instanceof Closeable) {
                    ((Closeable) objB).close();
                }
            }
            this.c.k0();
            if (this.b) {
                this.a.close();
            }
        }
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.d;
    }

    public final String toString() {
        return "HttpClient[" + this.a + ']';
    }
}
