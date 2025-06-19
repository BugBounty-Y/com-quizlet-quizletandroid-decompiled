package io.ktor.util.pipeline;

import androidx.glance.appwidget.protobuf.Z;
import java.util.List;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import kotlin.p;
import kotlin.q;
import kotlin.r;

/* loaded from: classes3.dex */
public final class l extends e {
    public final List b;
    public final k c;
    public Object d;
    public final kotlin.coroutines.h[] e;
    public int f;
    public int g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(Object initial, Object context, List blocks) {
        super(context);
        Intrinsics.checkNotNullParameter(initial, "initial");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(blocks, "blocks");
        this.b = blocks;
        this.c = new k(this);
        this.d = initial;
        this.e = new kotlin.coroutines.h[blocks.size()];
        this.f = -1;
    }

    @Override // io.ktor.util.pipeline.e
    public final Object a(Object obj, kotlin.coroutines.jvm.internal.c cVar) {
        this.g = 0;
        if (this.b.size() == 0) {
            return obj;
        }
        Intrinsics.checkNotNullParameter(obj, "<set-?>");
        this.d = obj;
        if (this.f < 0) {
            return c(cVar);
        }
        throw new IllegalStateException("Already started");
    }

    @Override // io.ktor.util.pipeline.e
    public final Object b() {
        return this.d;
    }

    @Override // io.ktor.util.pipeline.e
    public final Object c(kotlin.coroutines.h frame) {
        Object obj;
        if (this.g == this.b.size()) {
            obj = this.d;
        } else {
            kotlin.coroutines.h continuation = kotlin.coroutines.intrinsics.h.b(frame);
            Intrinsics.checkNotNullParameter(continuation, "continuation");
            int i = this.f + 1;
            this.f = i;
            kotlin.coroutines.h[] hVarArr = this.e;
            hVarArr[i] = continuation;
            if (e(true)) {
                int i2 = this.f;
                if (i2 < 0) {
                    throw new IllegalStateException("No more continuations to resume");
                }
                this.f = i2 - 1;
                hVarArr[i2] = null;
                obj = this.d;
            } else {
                obj = kotlin.coroutines.intrinsics.a.a;
            }
        }
        if (obj == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return obj;
    }

    @Override // io.ktor.util.pipeline.e
    public final Object d(Object obj, kotlin.coroutines.h hVar) {
        Intrinsics.checkNotNullParameter(obj, "<set-?>");
        this.d = obj;
        return c(hVar);
    }

    public final boolean e(boolean z) {
        kotlin.jvm.functions.c interceptor;
        Object subject;
        k continuation;
        do {
            int i = this.g;
            List list = this.b;
            if (i == list.size()) {
                if (z) {
                    return true;
                }
                p pVar = r.b;
                g(this.d);
                return false;
            }
            this.g = i + 1;
            interceptor = (kotlin.jvm.functions.c) list.get(i);
            try {
                subject = this.d;
                continuation = this.c;
                Intrinsics.checkNotNullParameter(interceptor, "interceptor");
                Intrinsics.checkNotNullParameter(this, "context");
                Intrinsics.checkNotNullParameter(subject, "subject");
                Intrinsics.checkNotNullParameter(continuation, "continuation");
                O.d(3, interceptor);
            } catch (Throwable th) {
                p pVar2 = r.b;
                g(Z.b(th));
                return false;
            }
        } while (interceptor.invoke(this, subject, continuation) != kotlin.coroutines.intrinsics.a.a);
        return false;
    }

    public final void g(Object obj) {
        int i = this.f;
        if (i < 0) {
            throw new IllegalStateException("No more continuations to resume");
        }
        kotlin.coroutines.h[] hVarArr = this.e;
        kotlin.coroutines.h continuation = hVarArr[i];
        Intrinsics.d(continuation);
        int i2 = this.f;
        this.f = i2 - 1;
        hVarArr[i2] = null;
        p pVar = r.b;
        if (!(obj instanceof q)) {
            continuation.resumeWith(obj);
            return;
        }
        Throwable exception = r.a(obj);
        Intrinsics.d(exception);
        Intrinsics.checkNotNullParameter(exception, "exception");
        Intrinsics.checkNotNullParameter(continuation, "continuation");
        try {
            exception.getCause();
            Intrinsics.checkNotNullParameter(exception, "<this>");
        } catch (Throwable unused) {
        }
        p pVar2 = r.b;
        continuation.resumeWith(Z.b(exception));
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.c.getContext();
    }
}
