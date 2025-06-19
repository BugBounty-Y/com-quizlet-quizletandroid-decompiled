package assistantMode.refactored.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = e.class)
/* loaded from: classes.dex */
public final class f implements serialization.b {

    @NotNull
    public static final ImageLicense$Companion Companion;
    public static final /* synthetic */ f[] b;
    public final int a;

    static {
        f[] fVarArr = {new f("USER_UPLOADED", 0, 1), new f("FLICKR", 1, 2)};
        b = fVarArr;
        AbstractC3328d.f(fVarArr);
        Companion = new ImageLicense$Companion();
    }

    public f(String str, int i, int i2) {
        this.a = i2;
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) b.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
