package androidx.glance;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class t {
    public static final t a;
    public static final /* synthetic */ t[] b;

    static {
        t tVar = new t("Visible", 0);
        a = tVar;
        b = new t[]{tVar, new t("Invisible", 1), new t("Gone", 2)};
    }

    public static t valueOf(String str) {
        return (t) Enum.valueOf(t.class, str);
    }

    public static t[] values() {
        return (t[]) b.clone();
    }
}
