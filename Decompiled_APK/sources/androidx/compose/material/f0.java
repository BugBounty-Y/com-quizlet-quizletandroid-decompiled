package androidx.compose.material;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class f0 {
    public static final f0 a;
    public static final f0 b;
    public static final f0 c;
    public static final /* synthetic */ f0[] d;

    static {
        f0 f0Var = new f0("Hidden", 0);
        a = f0Var;
        f0 f0Var2 = new f0("Expanded", 1);
        b = f0Var2;
        f0 f0Var3 = new f0("HalfExpanded", 2);
        c = f0Var3;
        f0[] f0VarArr = {f0Var, f0Var2, f0Var3};
        d = f0VarArr;
        AbstractC3328d.f(f0VarArr);
    }

    public static f0 valueOf(String str) {
        return (f0) Enum.valueOf(f0.class, str);
    }

    public static f0[] values() {
        return (f0[]) d.clone();
    }
}
