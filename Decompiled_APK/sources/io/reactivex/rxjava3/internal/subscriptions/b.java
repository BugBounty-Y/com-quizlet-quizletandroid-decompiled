package io.reactivex.rxjava3.internal.subscriptions;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class b implements io.reactivex.rxjava3.operators.b, org.reactivestreams.b {
    public static final b a;
    public static final /* synthetic */ b[] b;

    static {
        b bVar = new b("INSTANCE", 0);
        a = bVar;
        b = new b[]{bVar};
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) b.clone();
    }

    @Override // org.reactivestreams.b
    public final void cancel() {
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
    }

    @Override // org.reactivestreams.b
    public final void e(long j) {
        c.c(j);
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return true;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean offer(Object obj) {
        throw new UnsupportedOperationException("Should not be called!");
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        return null;
    }

    @Override // java.lang.Enum
    public final String toString() {
        return "EmptySubscription";
    }
}
