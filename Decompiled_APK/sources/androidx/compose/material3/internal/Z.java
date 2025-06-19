package androidx.compose.material3.internal;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class Z {
    public static final Z a;
    public static final Z b;
    public static final /* synthetic */ Z[] c;

    static {
        Z z = new Z("Filled", 0);
        a = z;
        Z z2 = new Z("Outlined", 1);
        b = z2;
        c = new Z[]{z, z2};
    }

    public static Z valueOf(String str) {
        return (Z) Enum.valueOf(Z.class, str);
    }

    public static Z[] values() {
        return (Z[]) c.clone();
    }
}
