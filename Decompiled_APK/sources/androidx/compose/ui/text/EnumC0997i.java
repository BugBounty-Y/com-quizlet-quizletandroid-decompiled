package androidx.compose.ui.text;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: androidx.compose.ui.text.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC0997i {
    public static final EnumC0997i a;
    public static final EnumC0997i b;
    public static final EnumC0997i c;
    public static final EnumC0997i d;
    public static final EnumC0997i e;
    public static final EnumC0997i f;
    public static final EnumC0997i g;
    public static final /* synthetic */ EnumC0997i[] h;

    static {
        EnumC0997i enumC0997i = new EnumC0997i("Paragraph", 0);
        a = enumC0997i;
        EnumC0997i enumC0997i2 = new EnumC0997i("Span", 1);
        b = enumC0997i2;
        EnumC0997i enumC0997i3 = new EnumC0997i("VerbatimTts", 2);
        c = enumC0997i3;
        EnumC0997i enumC0997i4 = new EnumC0997i("Url", 3);
        d = enumC0997i4;
        EnumC0997i enumC0997i5 = new EnumC0997i("Link", 4);
        e = enumC0997i5;
        EnumC0997i enumC0997i6 = new EnumC0997i("Clickable", 5);
        f = enumC0997i6;
        EnumC0997i enumC0997i7 = new EnumC0997i("String", 6);
        g = enumC0997i7;
        h = new EnumC0997i[]{enumC0997i, enumC0997i2, enumC0997i3, enumC0997i4, enumC0997i5, enumC0997i6, enumC0997i7};
    }

    public static EnumC0997i valueOf(String str) {
        return (EnumC0997i) Enum.valueOf(EnumC0997i.class, str);
    }

    public static EnumC0997i[] values() {
        return (EnumC0997i[]) h.clone();
    }
}
