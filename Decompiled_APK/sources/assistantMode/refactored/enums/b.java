package assistantMode.refactored.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = a.class)
/* loaded from: classes.dex */
public final class b implements serialization.b {

    @NotNull
    public static final ImageDownloadState$Companion Companion;
    public static final /* synthetic */ b[] b;
    public final int a;

    static {
        b[] bVarArr = {new b("FALSE", 0, 0), new b("S3", 1, 1), new b("EXISTS_ON_FLICKR", 2, 2)};
        b = bVarArr;
        AbstractC3328d.f(bVarArr);
        Companion = new ImageDownloadState$Companion();
    }

    public b(String str, int i, int i2) {
        this.a = i2;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) b.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
