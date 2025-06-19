package kotlin.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class d implements Serializable {

    @NotNull
    private static final c b = new c(null);
    public final Class a;

    public d(Enum[] entries) {
        Intrinsics.checkNotNullParameter(entries, "entries");
        Class<?> componentType = entries.getClass().getComponentType();
        Intrinsics.d(componentType);
        this.a = componentType;
    }

    private final Object readResolve() {
        Object[] enumConstants = this.a.getEnumConstants();
        Intrinsics.checkNotNullExpressionValue(enumConstants, "getEnumConstants(...)");
        return AbstractC3328d.f((Enum[]) enumConstants);
    }
}
