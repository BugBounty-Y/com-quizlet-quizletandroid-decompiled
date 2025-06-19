package androidx.compose.animation;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class O {
    public static final O a;
    public static final O b;
    public static final O c;
    public static final /* synthetic */ O[] d;

    static {
        O o = new O("PreEnter", 0);
        a = o;
        O o2 = new O("Visible", 1);
        b = o2;
        O o3 = new O("PostExit", 2);
        c = o3;
        d = new O[]{o, o2, o3};
    }

    public static O valueOf(String str) {
        return (O) Enum.valueOf(O.class, str);
    }

    public static O[] values() {
        return (O[]) d.clone();
    }
}
