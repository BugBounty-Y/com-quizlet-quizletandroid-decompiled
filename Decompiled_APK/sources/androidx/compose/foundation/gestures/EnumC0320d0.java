package androidx.compose.foundation.gestures;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: androidx.compose.foundation.gestures.d0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC0320d0 {
    public static final EnumC0320d0 a;
    public static final EnumC0320d0 b;
    public static final /* synthetic */ EnumC0320d0[] c;

    static {
        EnumC0320d0 enumC0320d0 = new EnumC0320d0("Vertical", 0);
        a = enumC0320d0;
        EnumC0320d0 enumC0320d02 = new EnumC0320d0("Horizontal", 1);
        b = enumC0320d02;
        c = new EnumC0320d0[]{enumC0320d0, enumC0320d02};
    }

    public static EnumC0320d0 valueOf(String str) {
        return (EnumC0320d0) Enum.valueOf(EnumC0320d0.class, str);
    }

    public static EnumC0320d0[] values() {
        return (EnumC0320d0[]) c.clone();
    }
}
