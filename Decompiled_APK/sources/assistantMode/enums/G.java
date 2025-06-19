package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = F.class)
/* loaded from: classes.dex */
public final class G implements serialization.f {

    @NotNull
    public static final VideoProvider$Companion Companion;
    public static final /* synthetic */ G[] b;
    public final String a;

    static {
        G[] gArr = {new G("VIMEO", 0, "vimeo"), new G("YOUTUBE", 1, "youtube")};
        b = gArr;
        AbstractC3328d.f(gArr);
        Companion = new VideoProvider$Companion();
    }

    public G(String str, int i, String str2) {
        this.a = str2;
    }

    public static G valueOf(String str) {
        return (G) Enum.valueOf(G.class, str);
    }

    public static G[] values() {
        return (G[]) b.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
