package androidx.compose.ui.text.style;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class h {
    public static final h a;
    public static final h b;
    public static final /* synthetic */ h[] c;

    static {
        h hVar = new h("Ltr", 0);
        a = hVar;
        h hVar2 = new h("Rtl", 1);
        b = hVar2;
        c = new h[]{hVar, hVar2};
    }

    public static h valueOf(String str) {
        return (h) Enum.valueOf(h.class, str);
    }

    public static h[] values() {
        return (h[]) c.clone();
    }
}
