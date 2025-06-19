package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = v.class)
/* loaded from: classes.dex */
public final class w implements serialization.b {

    @NotNull
    public static final StudyPathGoal$Companion Companion;
    public static final w b;
    public static final w c;
    public static final w d;
    public static final w e;
    public static final /* synthetic */ w[] f;
    public static final /* synthetic */ kotlin.enums.b g;
    public final int a;

    static {
        w wVar = new w("FAMILIARITY", 0, 0);
        b = wVar;
        w wVar2 = new w("MEMORIZATION", 1, 1);
        c = wVar2;
        w wVar3 = new w("CHALLENGE", 2, 2);
        d = wVar3;
        w wVar4 = new w("UNDERSTANDING", 3, 3);
        e = wVar4;
        w[] wVarArr = {wVar, wVar2, wVar3, wVar4};
        f = wVarArr;
        g = AbstractC3328d.f(wVarArr);
        Companion = new StudyPathGoal$Companion();
    }

    public w(String str, int i, int i2) {
        this.a = i2;
    }

    public static w valueOf(String str) {
        return (w) Enum.valueOf(w.class, str);
    }

    public static w[] values() {
        return (w[]) f.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
