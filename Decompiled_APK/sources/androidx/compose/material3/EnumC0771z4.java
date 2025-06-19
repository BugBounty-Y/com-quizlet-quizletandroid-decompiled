package androidx.compose.material3;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: androidx.compose.material3.z4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC0771z4 {
    public static final EnumC0771z4 a;
    public static final EnumC0771z4 b;
    public static final EnumC0771z4 c;
    public static final /* synthetic */ EnumC0771z4[] d;

    static {
        EnumC0771z4 enumC0771z4 = new EnumC0771z4("Tabs", 0);
        a = enumC0771z4;
        EnumC0771z4 enumC0771z42 = new EnumC0771z4("Divider", 1);
        b = enumC0771z42;
        EnumC0771z4 enumC0771z43 = new EnumC0771z4("Indicator", 2);
        c = enumC0771z43;
        d = new EnumC0771z4[]{enumC0771z4, enumC0771z42, enumC0771z43};
    }

    public static EnumC0771z4 valueOf(String str) {
        return (EnumC0771z4) Enum.valueOf(EnumC0771z4.class, str);
    }

    public static EnumC0771z4[] values() {
        return (EnumC0771z4[]) d.clone();
    }
}
