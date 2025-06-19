package androidx.compose.material3;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class U3 {
    public static final U3 a;
    public static final /* synthetic */ U3[] b;

    static {
        U3 u3 = new U3("Dismissed", 0);
        a = u3;
        b = new U3[]{u3, new U3("ActionPerformed", 1)};
    }

    public static U3 valueOf(String str) {
        return (U3) Enum.valueOf(U3.class, str);
    }

    public static U3[] values() {
        return (U3[]) b.clone();
    }
}
