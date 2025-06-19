package androidx.compose.material3.internal;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class B {
    public static final B a;
    public static final B b;
    public static final B c;
    public static final /* synthetic */ B[] d;

    static {
        B b2 = new B("Focused", 0);
        a = b2;
        B b3 = new B("UnfocusedEmpty", 1);
        b = b3;
        B b4 = new B("UnfocusedNotEmpty", 2);
        c = b4;
        d = new B[]{b2, b3, b4};
    }

    public static B valueOf(String str) {
        return (B) Enum.valueOf(B.class, str);
    }

    public static B[] values() {
        return (B[]) d.clone();
    }
}
