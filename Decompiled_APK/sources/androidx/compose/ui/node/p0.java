package androidx.compose.ui.node;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class p0 {
    public static final p0 a;
    public static final p0 b;
    public static final p0 c;
    public static final /* synthetic */ p0[] d;

    static {
        p0 p0Var = new p0("ContinueTraversal", 0);
        a = p0Var;
        p0 p0Var2 = new p0("SkipSubtreeAndContinueTraversal", 1);
        b = p0Var2;
        p0 p0Var3 = new p0("CancelTraversal", 2);
        c = p0Var3;
        d = new p0[]{p0Var, p0Var2, p0Var3};
    }

    public static p0 valueOf(String str) {
        return (p0) Enum.valueOf(p0.class, str);
    }

    public static p0[] values() {
        return (p0[]) d.clone();
    }
}
