package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = C1449c.class)
/* renamed from: assistantMode.enums.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC1450d implements serialization.f {

    @NotNull
    public static final AssistantCheckpointProgressState$Companion Companion;
    public static final EnumC1450d b;
    public static final EnumC1450d c;
    public static final EnumC1450d d;
    public static final /* synthetic */ EnumC1450d[] e;
    public final String a;

    static {
        EnumC1450d enumC1450d = new EnumC1450d("ROUND_CHECKPOINT", 0, "ROUND_CHECKPOINT");
        b = enumC1450d;
        EnumC1450d enumC1450d2 = new EnumC1450d("LEARN_COMPLETION_CHECKPOINT", 1, "LEARN_COMPLETION_CHECKPOINT");
        c = enumC1450d2;
        EnumC1450d enumC1450d3 = new EnumC1450d("POST_COMPLETION_CHECKPOINT", 2, "POST_COMPLETION_CHECKPOINT");
        d = enumC1450d3;
        EnumC1450d[] enumC1450dArr = {enumC1450d, enumC1450d2, enumC1450d3};
        e = enumC1450dArr;
        AbstractC3328d.f(enumC1450dArr);
        Companion = new AssistantCheckpointProgressState$Companion();
    }

    public EnumC1450d(String str, int i, String str2) {
        this.a = str2;
    }

    public static EnumC1450d valueOf(String str) {
        return (EnumC1450d) Enum.valueOf(EnumC1450d.class, str);
    }

    public static EnumC1450d[] values() {
        return (EnumC1450d[]) e.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
