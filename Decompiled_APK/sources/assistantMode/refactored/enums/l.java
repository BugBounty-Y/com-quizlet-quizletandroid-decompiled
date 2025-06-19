package assistantMode.refactored.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = k.class)
/* loaded from: classes.dex */
public final class l implements serialization.b {

    @NotNull
    public static final StudiableItemType$Companion Companion;
    public static final /* synthetic */ l[] b;
    public final int a;

    static {
        l[] lVarArr = {new l("MULTIPLE_CHOICE_QUESTION", 0, 1), new l("N_SIDED_CARD", 1, 2)};
        b = lVarArr;
        AbstractC3328d.f(lVarArr);
        Companion = new StudiableItemType$Companion();
    }

    public l(String str, int i, int i2) {
        this.a = i2;
    }

    public static l valueOf(String str) {
        return (l) Enum.valueOf(l.class, str);
    }

    public static l[] values() {
        return (l[]) b.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
