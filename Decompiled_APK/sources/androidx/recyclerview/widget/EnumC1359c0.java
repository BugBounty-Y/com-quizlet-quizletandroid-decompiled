package androidx.recyclerview.widget;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: androidx.recyclerview.widget.c0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC1359c0 {
    public static final EnumC1359c0 a;
    public static final EnumC1359c0 b;
    public static final EnumC1359c0 c;
    public static final /* synthetic */ EnumC1359c0[] d;

    static {
        EnumC1359c0 enumC1359c0 = new EnumC1359c0("ALLOW", 0);
        a = enumC1359c0;
        EnumC1359c0 enumC1359c02 = new EnumC1359c0("PREVENT_WHEN_EMPTY", 1);
        b = enumC1359c02;
        EnumC1359c0 enumC1359c03 = new EnumC1359c0("PREVENT", 2);
        c = enumC1359c03;
        d = new EnumC1359c0[]{enumC1359c0, enumC1359c02, enumC1359c03};
    }

    public static EnumC1359c0 valueOf(String str) {
        return (EnumC1359c0) Enum.valueOf(EnumC1359c0.class, str);
    }

    public static EnumC1359c0[] values() {
        return (EnumC1359c0[]) d.clone();
    }
}
