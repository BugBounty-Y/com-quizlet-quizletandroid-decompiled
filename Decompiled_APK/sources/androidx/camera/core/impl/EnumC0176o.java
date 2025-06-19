package androidx.camera.core.impl;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: androidx.camera.core.impl.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC0176o {
    public static final EnumC0176o a;
    public static final EnumC0176o b;
    public static final EnumC0176o c;
    public static final EnumC0176o d;
    public static final EnumC0176o e;
    public static final /* synthetic */ EnumC0176o[] f;

    static {
        EnumC0176o enumC0176o = new EnumC0176o("UNKNOWN", 0);
        a = enumC0176o;
        EnumC0176o enumC0176o2 = new EnumC0176o("INACTIVE", 1);
        b = enumC0176o2;
        EnumC0176o enumC0176o3 = new EnumC0176o("METERING", 2);
        c = enumC0176o3;
        EnumC0176o enumC0176o4 = new EnumC0176o("CONVERGED", 3);
        d = enumC0176o4;
        EnumC0176o enumC0176o5 = new EnumC0176o("LOCKED", 4);
        e = enumC0176o5;
        f = new EnumC0176o[]{enumC0176o, enumC0176o2, enumC0176o3, enumC0176o4, enumC0176o5};
    }

    public static EnumC0176o valueOf(String str) {
        return (EnumC0176o) Enum.valueOf(EnumC0176o.class, str);
    }

    public static EnumC0176o[] values() {
        return (EnumC0176o[]) f.clone();
    }
}
