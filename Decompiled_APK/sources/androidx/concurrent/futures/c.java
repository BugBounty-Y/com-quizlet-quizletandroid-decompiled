package androidx.concurrent.futures;

/* loaded from: classes.dex */
public final class c {
    public final Throwable a;

    static {
        new c(new b("Failure occurred while trying to finish a future.", 0));
    }

    public c(Throwable th) {
        boolean z = h.d;
        th.getClass();
        this.a = th;
    }
}
