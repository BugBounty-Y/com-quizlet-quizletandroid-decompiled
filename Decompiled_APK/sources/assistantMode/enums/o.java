package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = n.class)
/* loaded from: classes.dex */
public final class o implements serialization.b {

    @NotNull
    public static final StudiableMetadataCategory$Companion Companion;
    public static final /* synthetic */ o[] b;
    public final int a;

    static {
        o[] oVarArr = {new o("REWORDING", 0, 1), new o("CONTEXT", 1, 2)};
        b = oVarArr;
        AbstractC3328d.f(oVarArr);
        Companion = new StudiableMetadataCategory$Companion();
    }

    public o(String str, int i, int i2) {
        this.a = i2;
    }

    public static o valueOf(String str) {
        return (o) Enum.valueOf(o.class, str);
    }

    public static o[] values() {
        return (o[]) b.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
