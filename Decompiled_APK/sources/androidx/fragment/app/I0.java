package androidx.fragment.app;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class I0 {
    public static final I0 a;
    public static final I0 b;
    public static final I0 c;
    public static final /* synthetic */ I0[] d;

    static {
        I0 i0 = new I0("NONE", 0);
        a = i0;
        I0 i02 = new I0("ADDING", 1);
        b = i02;
        I0 i03 = new I0("REMOVING", 2);
        c = i03;
        d = new I0[]{i0, i02, i03};
    }

    public static I0 valueOf(String str) {
        return (I0) Enum.valueOf(I0.class, str);
    }

    public static I0[] values() {
        return (I0[]) d.clone();
    }
}
