package kotlin.time;

import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class h {

    @NotNull
    public static final h a = new h();

    public final TimeMark a() {
        f.a.getClass();
        return new g(System.nanoTime() - f.b);
    }

    public final String toString() {
        f.a.getClass();
        return "TimeSource(System.nanoTime())";
    }
}
