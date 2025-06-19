package androidx.paging;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class U0 {
    public static final U0 a;
    public static final /* synthetic */ U0[] b;

    static {
        U0 u0 = new U0("LAUNCH_INITIAL_REFRESH", 0);
        a = u0;
        b = new U0[]{u0, new U0("SKIP_INITIAL_REFRESH", 1)};
    }

    public static U0 valueOf(String str) {
        return (U0) Enum.valueOf(U0.class, str);
    }

    public static U0[] values() {
        return (U0[]) b.clone();
    }
}
