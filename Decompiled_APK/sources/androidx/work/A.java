package androidx.work;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class A {
    public static final A a;
    public static final A b;
    public static final A c;
    public static final A d;
    public static final A e;
    public static final A f;
    public static final /* synthetic */ A[] g;

    static {
        A a2 = new A("NOT_REQUIRED", 0);
        a = a2;
        A a3 = new A("CONNECTED", 1);
        b = a3;
        A a4 = new A("UNMETERED", 2);
        c = a4;
        A a5 = new A("NOT_ROAMING", 3);
        d = a5;
        A a6 = new A("METERED", 4);
        e = a6;
        A a7 = new A("TEMPORARILY_UNMETERED", 5);
        f = a7;
        g = new A[]{a2, a3, a4, a5, a6, a7};
    }

    public static A valueOf(String str) {
        return (A) Enum.valueOf(A.class, str);
    }

    public static A[] values() {
        return (A[]) g.clone();
    }
}
