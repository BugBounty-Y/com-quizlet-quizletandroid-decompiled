package okhttp3.internal.http2;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public static final okio.k d;
    public static final okio.k e;
    public static final okio.k f;
    public static final okio.k g;
    public static final okio.k h;
    public static final okio.k i;
    public final okio.k a;
    public final okio.k b;
    public final int c;

    static {
        okio.k kVar = okio.k.d;
        d = com.quizlet.quizletandroid.ui.common.images.capture.b.i(":");
        e = com.quizlet.quizletandroid.ui.common.images.capture.b.i(":status");
        f = com.quizlet.quizletandroid.ui.common.images.capture.b.i(":method");
        g = com.quizlet.quizletandroid.ui.common.images.capture.b.i(":path");
        h = com.quizlet.quizletandroid.ui.common.images.capture.b.i(":scheme");
        i = com.quizlet.quizletandroid.ui.common.images.capture.b.i(":authority");
    }

    public b(okio.k name, okio.k value) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(value, "value");
        this.a = name;
        this.b = value;
        this.c = value.d() + name.d() + 32;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return this.a.s() + ": " + this.b.s();
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public b(String name, String value) {
        this(com.quizlet.quizletandroid.ui.common.images.capture.b.i(name), com.quizlet.quizletandroid.ui.common.images.capture.b.i(value));
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(value, "value");
        okio.k kVar = okio.k.d;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public b(okio.k name, String value) {
        this(name, com.quizlet.quizletandroid.ui.common.images.capture.b.i(value));
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(value, "value");
        okio.k kVar = okio.k.d;
    }
}
