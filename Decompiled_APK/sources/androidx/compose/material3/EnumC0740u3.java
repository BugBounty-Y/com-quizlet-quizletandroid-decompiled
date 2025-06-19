package androidx.compose.material3;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: androidx.compose.material3.u3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC0740u3 {
    public static final EnumC0740u3 a;
    public static final EnumC0740u3 b;
    public static final EnumC0740u3 c;
    public static final EnumC0740u3 d;
    public static final EnumC0740u3 e;
    public static final /* synthetic */ EnumC0740u3[] f;

    static {
        EnumC0740u3 enumC0740u3 = new EnumC0740u3("TopBar", 0);
        a = enumC0740u3;
        EnumC0740u3 enumC0740u32 = new EnumC0740u3("MainContent", 1);
        b = enumC0740u32;
        EnumC0740u3 enumC0740u33 = new EnumC0740u3("Snackbar", 2);
        c = enumC0740u33;
        EnumC0740u3 enumC0740u34 = new EnumC0740u3("Fab", 3);
        d = enumC0740u34;
        EnumC0740u3 enumC0740u35 = new EnumC0740u3("BottomBar", 4);
        e = enumC0740u35;
        f = new EnumC0740u3[]{enumC0740u3, enumC0740u32, enumC0740u33, enumC0740u34, enumC0740u35};
    }

    public static EnumC0740u3 valueOf(String str) {
        return (EnumC0740u3) Enum.valueOf(EnumC0740u3.class, str);
    }

    public static EnumC0740u3[] values() {
        return (EnumC0740u3[]) f.clone();
    }
}
