package androidx.work;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class J {
    public static final J a;
    public static final J b;
    public static final /* synthetic */ J[] c;

    static {
        J j = new J("RUN_AS_NON_EXPEDITED_WORK_REQUEST", 0);
        a = j;
        J j2 = new J("DROP_WORK_REQUEST", 1);
        b = j2;
        c = new J[]{j, j2};
    }

    public static J valueOf(String str) {
        return (J) Enum.valueOf(J.class, str);
    }

    public static J[] values() {
        return (J[]) c.clone();
    }
}
