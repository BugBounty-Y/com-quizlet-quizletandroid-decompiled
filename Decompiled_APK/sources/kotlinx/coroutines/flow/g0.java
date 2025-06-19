package kotlinx.coroutines.flow;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class g0 {
    public static final g0 a;
    public static final g0 b;
    public static final g0 c;
    public static final /* synthetic */ g0[] d;

    static {
        g0 g0Var = new g0("START", 0);
        a = g0Var;
        g0 g0Var2 = new g0("STOP", 1);
        b = g0Var2;
        g0 g0Var3 = new g0("STOP_AND_RESET_REPLAY_CACHE", 2);
        c = g0Var3;
        g0[] g0VarArr = {g0Var, g0Var2, g0Var3};
        d = g0VarArr;
        AbstractC3328d.f(g0VarArr);
    }

    public static g0 valueOf(String str) {
        return (g0) Enum.valueOf(g0.class, str);
    }

    public static g0[] values() {
        return (g0[]) d.clone();
    }
}
