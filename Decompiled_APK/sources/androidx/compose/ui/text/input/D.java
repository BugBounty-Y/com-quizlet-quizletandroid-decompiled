package androidx.compose.ui.text.input;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class D {
    public static final D a;
    public static final D b;
    public static final D c;
    public static final D d;
    public static final /* synthetic */ D[] e;

    static {
        D d2 = new D("StartInput", 0);
        a = d2;
        D d3 = new D("StopInput", 1);
        b = d3;
        D d4 = new D("ShowKeyboard", 2);
        c = d4;
        D d5 = new D("HideKeyboard", 3);
        d = d5;
        e = new D[]{d2, d3, d4, d5};
    }

    public static D valueOf(String str) {
        return (D) Enum.valueOf(D.class, str);
    }

    public static D[] values() {
        return (D[]) e.clone();
    }
}
