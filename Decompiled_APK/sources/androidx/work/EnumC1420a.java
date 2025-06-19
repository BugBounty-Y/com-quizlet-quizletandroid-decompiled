package androidx.work;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: androidx.work.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC1420a {
    public static final EnumC1420a a;
    public static final EnumC1420a b;
    public static final /* synthetic */ EnumC1420a[] c;

    static {
        EnumC1420a enumC1420a = new EnumC1420a("EXPONENTIAL", 0);
        a = enumC1420a;
        EnumC1420a enumC1420a2 = new EnumC1420a("LINEAR", 1);
        b = enumC1420a2;
        c = new EnumC1420a[]{enumC1420a, enumC1420a2};
    }

    public static EnumC1420a valueOf(String str) {
        return (EnumC1420a) Enum.valueOf(EnumC1420a.class, str);
    }

    public static EnumC1420a[] values() {
        return (EnumC1420a[]) c.clone();
    }
}
