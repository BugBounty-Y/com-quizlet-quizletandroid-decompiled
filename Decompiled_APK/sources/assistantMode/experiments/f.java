package assistantMode.experiments;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = e.class)
/* loaded from: classes.dex */
public final class f implements serialization.f {

    @NotNull
    public static final LearnProgressBarExperimentVariant$Companion Companion;
    public static final f b;
    public static final f c;
    public static final /* synthetic */ f[] d;
    public final String a;

    static {
        f fVar = new f("Control", 0, "control");
        f fVar2 = new f("VariantA", 1, "variantA");
        b = fVar2;
        f fVar3 = new f("VariantB", 2, "variantB");
        c = fVar3;
        f[] fVarArr = {fVar, fVar2, fVar3};
        d = fVarArr;
        AbstractC3328d.f(fVarArr);
        Companion = new LearnProgressBarExperimentVariant$Companion();
    }

    public f(String str, int i, String str2) {
        this.a = str2;
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) d.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
