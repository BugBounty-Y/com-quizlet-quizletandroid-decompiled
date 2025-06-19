package assistantMode.experiments;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = c.class)
/* loaded from: classes.dex */
public final class d implements serialization.f {

    @NotNull
    public static final GranularStudyDirectionVariantV2$Companion Companion;
    public static final /* synthetic */ d[] b;
    public final String a;

    static {
        d[] dVarArr = {new d("CONTROL", 0, "control"), new d("V2", 1, "v2")};
        b = dVarArr;
        AbstractC3328d.f(dVarArr);
        Companion = new GranularStudyDirectionVariantV2$Companion();
    }

    public d(String str, int i, String str2) {
        this.a = str2;
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) b.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
