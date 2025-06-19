package io.ktor.client.engine.okhttp;

import io.ktor.client.plugins.C4864k;
import io.ktor.utils.io.n;
import java.io.IOException;
import kotlin.C4937f;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.F;
import okhttp3.w;
import okio.AbstractC5085b;
import okio.C5087d;
import okio.InterfaceC5092i;

/* loaded from: classes3.dex */
public final class i extends F {
    public final Long a;
    public final com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a b;

    public i(Long l, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a block) {
        Intrinsics.checkNotNullParameter(block, "block");
        this.a = l;
        this.b = block;
    }

    @Override // okhttp3.F
    public final long a() {
        Long l = this.a;
        if (l != null) {
            return l.longValue();
        }
        return -1L;
    }

    @Override // okhttp3.F
    public final w b() {
        return null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r6v4, types: [java.lang.Throwable] */
    /* JADX WARN: Type inference failed for: r6v6 */
    /* JADX WARN: Type inference failed for: r6v7 */
    /* JADX WARN: Type inference failed for: r6v8 */
    @Override // okhttp3.F
    public final void d(InterfaceC5092i sink) throws IOException {
        ?? r6;
        Intrinsics.checkNotNullParameter(sink, "sink");
        try {
            n nVar = (n) this.b.invoke();
            Intrinsics.checkNotNullParameter(nVar, "<this>");
            C5087d c5087dJ = AbstractC5085b.j(new C4864k(nVar, 1));
            Long th = null;
            try {
                Long lValueOf = Long.valueOf(sink.M(c5087dJ));
                try {
                    c5087dJ.close();
                } catch (Throwable th2) {
                    th = th2;
                }
                Long l = th;
                th = lValueOf;
                r6 = l;
            } catch (Throwable th3) {
                try {
                    c5087dJ.close();
                    r6 = th3;
                } catch (Throwable th4) {
                    C4937f.a(th3, th4);
                    r6 = th3;
                }
            }
            if (r6 != 0) {
                throw r6;
            }
            th.getClass();
        } catch (IOException e) {
            throw e;
        } catch (Throwable cause) {
            Intrinsics.checkNotNullParameter(cause, "cause");
            throw new StreamAdapterIOException(cause);
        }
    }
}
