package androidx.work;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: androidx.work.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC1441o {
    public static final EnumC1441o a;
    public static final EnumC1441o b;
    public static final EnumC1441o c;
    public static final EnumC1441o d;
    public static final /* synthetic */ EnumC1441o[] e;

    static {
        EnumC1441o enumC1441o = new EnumC1441o("REPLACE", 0);
        a = enumC1441o;
        EnumC1441o enumC1441o2 = new EnumC1441o("KEEP", 1);
        b = enumC1441o2;
        EnumC1441o enumC1441o3 = new EnumC1441o("APPEND", 2);
        c = enumC1441o3;
        EnumC1441o enumC1441o4 = new EnumC1441o("APPEND_OR_REPLACE", 3);
        d = enumC1441o4;
        e = new EnumC1441o[]{enumC1441o, enumC1441o2, enumC1441o3, enumC1441o4};
    }

    public static EnumC1441o valueOf(String str) {
        return (EnumC1441o) Enum.valueOf(EnumC1441o.class, str);
    }

    public static EnumC1441o[] values() {
        return (EnumC1441o[]) e.clone();
    }
}
