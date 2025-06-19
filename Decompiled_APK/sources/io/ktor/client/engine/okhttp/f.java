package io.ktor.client.engine.okhttp;

import androidx.compose.ui.text.font.o;
import com.quizlet.search.composables.E;
import io.ktor.client.plugins.X;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.k;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;
import kotlinx.coroutines.A0;
import kotlinx.coroutines.C4977c0;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.D;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.InterfaceC5034s;

/* loaded from: classes3.dex */
public final class f extends io.ktor.client.engine.f {
    public static final u i = l.b(new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(29));
    public final b d;
    public final Set e;
    public final CoroutineContext f;
    public final CoroutineContext g;
    public final Map h;

    public f(b config) {
        Intrinsics.checkNotNullParameter(config, "config");
        this.d = config;
        io.ktor.client.engine.g[] elements = {X.a, io.ktor.client.plugins.websocket.a.a, io.ktor.client.plugins.sse.a.a};
        Intrinsics.checkNotNullParameter(elements, "elements");
        this.e = C4933y.T(elements);
        E supplier = new E(1, this, f.class, "createOkHttpClient", "createOkHttpClient(Lio/ktor/client/plugins/HttpTimeoutConfig;)Lokhttp3/OkHttpClient;", 0, 11);
        com.sdk.growthbook.utils.a close = new com.sdk.growthbook.utils.a(5);
        int i2 = config.c;
        Intrinsics.checkNotNullParameter(supplier, "supplier");
        Intrinsics.checkNotNullParameter(close, "close");
        Map mapSynchronizedMap = Collections.synchronizedMap(new io.ktor.util.h(supplier, close, i2));
        Intrinsics.checkNotNullExpressionValue(mapSynchronizedMap, "synchronizedMap(...)");
        this.h = mapSynchronizedMap;
        CoroutineContext.Element element = super.getCoroutineContext().get(C5023i0.a);
        Intrinsics.d(element);
        CoroutineContext coroutineContextC = k.c(new o(C5041z.a, 13), new A0((InterfaceC5025j0) element));
        this.f = coroutineContextC;
        this.g = super.getCoroutineContext().plus(coroutineContextC);
        kotlinx.coroutines.E.z(C4977c0.a, super.getCoroutineContext(), D.c, new c(this, null));
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x001b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(io.ktor.client.request.d r20, kotlin.coroutines.jvm.internal.c r21) {
        /*
            Method dump skipped, instructions count: 598
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.engine.okhttp.f.a(io.ktor.client.request.d, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // io.ktor.client.engine.f, java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        super.close();
        CoroutineContext.Element element = this.f.get(C5023i0.a);
        Intrinsics.e(element, "null cannot be cast to non-null type kotlinx.coroutines.CompletableJob");
        ((C5027k0) ((InterfaceC5034s) element)).k0();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x001b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(okhttp3.A r18, okhttp3.C r19, kotlin.coroutines.CoroutineContext r20, io.ktor.client.request.d r21, kotlin.coroutines.jvm.internal.c r22) {
        /*
            Method dump skipped, instructions count: 283
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.engine.okhttp.f.d(okhttp3.A, okhttp3.C, kotlin.coroutines.CoroutineContext, io.ktor.client.request.d, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // io.ktor.client.engine.f, kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.g;
    }
}
