package androidx.compose.material3;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: androidx.compose.material3.h4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC0630h4 {
    public static final EnumC0630h4 a;
    public static final EnumC0630h4 b;
    public static final EnumC0630h4 c;
    public static final /* synthetic */ EnumC0630h4[] d;

    static {
        EnumC0630h4 enumC0630h4 = new EnumC0630h4("StartToEnd", 0);
        a = enumC0630h4;
        EnumC0630h4 enumC0630h42 = new EnumC0630h4("EndToStart", 1);
        b = enumC0630h42;
        EnumC0630h4 enumC0630h43 = new EnumC0630h4("Settled", 2);
        c = enumC0630h43;
        d = new EnumC0630h4[]{enumC0630h4, enumC0630h42, enumC0630h43};
    }

    public static EnumC0630h4 valueOf(String str) {
        return (EnumC0630h4) Enum.valueOf(EnumC0630h4.class, str);
    }

    public static EnumC0630h4[] values() {
        return (EnumC0630h4[]) d.clone();
    }
}
