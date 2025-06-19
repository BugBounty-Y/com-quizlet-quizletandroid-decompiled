package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = C1447a.class)
/* renamed from: assistantMode.enums.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class EnumC1448b implements serialization.b {

    @NotNull
    public static final AnswerOption$Companion Companion;
    public static final EnumC1448b b;
    public static final EnumC1448b c;
    public static final EnumC1448b d;
    public static final /* synthetic */ EnumC1448b[] e;
    public final int a;

    static {
        EnumC1448b enumC1448b = new EnumC1448b("FALSE", 0, 0);
        EnumC1448b enumC1448b2 = new EnumC1448b("TRUE", 1, 1);
        EnumC1448b enumC1448b3 = new EnumC1448b("SKIP", 2, 2);
        b = enumC1448b3;
        EnumC1448b enumC1448b4 = new EnumC1448b("KNOW", 3, 3);
        c = enumC1448b4;
        EnumC1448b enumC1448b5 = new EnumC1448b("DO_NOT_KNOW", 4, 4);
        d = enumC1448b5;
        EnumC1448b[] enumC1448bArr = {enumC1448b, enumC1448b2, enumC1448b3, enumC1448b4, enumC1448b5, new EnumC1448b("NONE_OF_THE_ABOVE", 5, 5)};
        e = enumC1448bArr;
        AbstractC3328d.f(enumC1448bArr);
        Companion = new AnswerOption$Companion();
    }

    public EnumC1448b(String str, int i, int i2) {
        this.a = i2;
    }

    public static EnumC1448b valueOf(String str) {
        return (EnumC1448b) Enum.valueOf(EnumC1448b.class, str);
    }

    public static EnumC1448b[] values() {
        return (EnumC1448b[]) e.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
