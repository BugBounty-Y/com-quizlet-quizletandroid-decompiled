package androidx.compose.foundation.text;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class V {
    public static final V a;
    public static final V b;
    public static final V c;
    public static final /* synthetic */ V[] d;

    static {
        V v = new V("None", 0);
        a = v;
        V v2 = new V("Selection", 1);
        b = v2;
        V v3 = new V("Cursor", 2);
        c = v3;
        d = new V[]{v, v2, v3};
    }

    public static V valueOf(String str) {
        return (V) Enum.valueOf(V.class, str);
    }

    public static V[] values() {
        return (V[]) d.clone();
    }
}
