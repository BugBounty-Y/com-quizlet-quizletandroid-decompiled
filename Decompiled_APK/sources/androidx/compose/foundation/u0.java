package androidx.compose.foundation;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class u0 {
    public static final u0 a;
    public static final u0 b;
    public static final /* synthetic */ u0[] c;

    static {
        u0 u0Var = new u0("Default", 0);
        a = u0Var;
        u0 u0Var2 = new u0("UserInput", 1);
        b = u0Var2;
        c = new u0[]{u0Var, u0Var2, new u0("PreventUserInput", 2)};
    }

    public static u0 valueOf(String str) {
        return (u0) Enum.valueOf(u0.class, str);
    }

    public static u0[] values() {
        return (u0[]) c.clone();
    }
}
