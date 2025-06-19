package androidx.concurrent.futures;

import java.util.concurrent.CancellationException;

/* loaded from: classes.dex */
public final class a {
    public static final a c;
    public static final a d;
    public final boolean a;
    public final CancellationException b;

    static {
        if (h.d) {
            d = null;
            c = null;
        } else {
            d = new a(false, null);
            c = new a(true, null);
        }
    }

    public a(boolean z, CancellationException cancellationException) {
        this.a = z;
        this.b = cancellationException;
    }
}
