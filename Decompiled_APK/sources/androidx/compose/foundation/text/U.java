package androidx.compose.foundation.text;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class U {
    public static final U a;
    public static final U b;
    public static final U c;
    public static final /* synthetic */ U[] d;

    static {
        U u = new U("Cursor", 0);
        a = u;
        U u2 = new U("SelectionStart", 1);
        b = u2;
        U u3 = new U("SelectionEnd", 2);
        c = u3;
        d = new U[]{u, u2, u3};
    }

    public static U valueOf(String str) {
        return (U) Enum.valueOf(U.class, str);
    }

    public static U[] values() {
        return (U[]) d.clone();
    }
}
