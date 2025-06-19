package assistantMode.refactored.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = i.class)
/* loaded from: classes.dex */
public final class j implements serialization.b {

    @NotNull
    public static final StudiableContainerType$Companion Companion;
    public static final j b;
    public static final /* synthetic */ j[] c;
    public final int a;

    static {
        j jVar = new j("SET", 0, 1);
        b = jVar;
        j[] jVarArr = {jVar, new j("FOLDER", 1, 2), new j("PREP_PACK", 2, 3)};
        c = jVarArr;
        AbstractC3328d.f(jVarArr);
        Companion = new StudiableContainerType$Companion();
    }

    public j(String str, int i, int i2) {
        this.a = i2;
    }

    public static j valueOf(String str) {
        return (j) Enum.valueOf(j.class, str);
    }

    public static j[] values() {
        return (j[]) c.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
