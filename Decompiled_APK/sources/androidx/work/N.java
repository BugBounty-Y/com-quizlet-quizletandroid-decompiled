package androidx.work;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class N {
    public static final N a;
    public static final N b;
    public static final N c;
    public static final N d;
    public static final N e;
    public static final N f;
    public static final /* synthetic */ N[] g;

    static {
        N n = new N("ENQUEUED", 0);
        a = n;
        N n2 = new N("RUNNING", 1);
        b = n2;
        N n3 = new N("SUCCEEDED", 2);
        c = n3;
        N n4 = new N("FAILED", 3);
        d = n4;
        N n5 = new N("BLOCKED", 4);
        e = n5;
        N n6 = new N("CANCELLED", 5);
        f = n6;
        g = new N[]{n, n2, n3, n4, n5, n6};
    }

    public static N valueOf(String str) {
        return (N) Enum.valueOf(N.class, str);
    }

    public static N[] values() {
        return (N[]) g.clone();
    }

    public final boolean a() {
        return this == c || this == d || this == f;
    }
}
