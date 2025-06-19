package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = C1451e.class)
/* renamed from: assistantMode.enums.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC1452f implements serialization.b {

    @NotNull
    public static final Correctness$Companion Companion;
    public static final EnumC1452f b;
    public static final EnumC1452f c;
    public static final EnumC1452f d;
    public static final /* synthetic */ EnumC1452f[] e;
    public final int a;

    static {
        EnumC1452f enumC1452f = new EnumC1452f("INCORRECT", 0, 0);
        b = enumC1452f;
        EnumC1452f enumC1452f2 = new EnumC1452f("CORRECT", 1, 1);
        c = enumC1452f2;
        EnumC1452f enumC1452f3 = new EnumC1452f("SKIPPED", 2, 2);
        d = enumC1452f3;
        EnumC1452f[] enumC1452fArr = {enumC1452f, enumC1452f2, enumC1452f3, new EnumC1452f("INCORRECT_WITH_HINT", 3, 3), new EnumC1452f("CORRECT_WITH_HINT", 4, 4)};
        e = enumC1452fArr;
        AbstractC3328d.f(enumC1452fArr);
        Companion = new Correctness$Companion();
    }

    public EnumC1452f(String str, int i, int i2) {
        this.a = i2;
    }

    public static EnumC1452f valueOf(String str) {
        return (EnumC1452f) Enum.valueOf(EnumC1452f.class, str);
    }

    public static EnumC1452f[] values() {
        return (EnumC1452f[]) e.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
