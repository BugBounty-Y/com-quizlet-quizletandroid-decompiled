package assistantMode.refactored.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = m.class)
/* loaded from: classes.dex */
public final class n implements serialization.b {

    @NotNull
    public static final StudiableMediaConnectionType$Companion Companion;
    public static final /* synthetic */ n[] b;
    public final int a;

    static {
        n[] nVarArr = {new n("MULTIPLE_CHOICE_PROMPT", 0, 1), new n("MULTIPLE_CHOICE_HINT", 1, 2), new n("MULTIPLE_CHOICE_OPTION", 2, 3), new n("MULTIPLE_CHOICE_OPTION_EXPLANATION", 3, 4), new n("N_SIDED_CARD_SIDE", 4, 5), new n("CARD_SIDE_DISTRACTOR", 5, 6)};
        b = nVarArr;
        AbstractC3328d.f(nVarArr);
        Companion = new StudiableMediaConnectionType$Companion();
    }

    public n(String str, int i, int i2) {
        this.a = i2;
    }

    public static n valueOf(String str) {
        return (n) Enum.valueOf(n.class, str);
    }

    public static n[] values() {
        return (n[]) b.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
