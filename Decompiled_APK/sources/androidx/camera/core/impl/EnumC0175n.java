package androidx.camera.core.impl;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: androidx.camera.core.impl.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC0175n {
    public static final EnumC0175n a;
    public static final EnumC0175n b;
    public static final EnumC0175n c;
    public static final EnumC0175n d;
    public static final EnumC0175n e;
    public static final EnumC0175n f;
    public static final EnumC0175n g;
    public static final /* synthetic */ EnumC0175n[] h;

    static {
        EnumC0175n enumC0175n = new EnumC0175n("UNKNOWN", 0);
        a = enumC0175n;
        EnumC0175n enumC0175n2 = new EnumC0175n("INACTIVE", 1);
        b = enumC0175n2;
        EnumC0175n enumC0175n3 = new EnumC0175n("SCANNING", 2);
        c = enumC0175n3;
        EnumC0175n enumC0175n4 = new EnumC0175n("PASSIVE_FOCUSED", 3);
        d = enumC0175n4;
        EnumC0175n enumC0175n5 = new EnumC0175n("PASSIVE_NOT_FOCUSED", 4);
        e = enumC0175n5;
        EnumC0175n enumC0175n6 = new EnumC0175n("LOCKED_FOCUSED", 5);
        f = enumC0175n6;
        EnumC0175n enumC0175n7 = new EnumC0175n("LOCKED_NOT_FOCUSED", 6);
        g = enumC0175n7;
        h = new EnumC0175n[]{enumC0175n, enumC0175n2, enumC0175n3, enumC0175n4, enumC0175n5, enumC0175n6, enumC0175n7};
    }

    public static EnumC0175n valueOf(String str) {
        return (EnumC0175n) Enum.valueOf(EnumC0175n.class, str);
    }

    public static EnumC0175n[] values() {
        return (EnumC0175n[]) h.clone();
    }
}
