package assistantMode.refactored.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = c.class)
/* loaded from: classes.dex */
public final class d implements serialization.b {

    @NotNull
    public static final ImageFormat$Companion Companion;
    public static final /* synthetic */ d[] b;
    public final int a;

    static {
        d[] dVarArr = {new d("UNKNOWN", 0, 0), new d("WEBP", 1, 1), new d("GIF", 2, 2)};
        b = dVarArr;
        AbstractC3328d.f(dVarArr);
        Companion = new ImageFormat$Companion();
    }

    public d(String str, int i, int i2) {
        this.a = i2;
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) b.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
