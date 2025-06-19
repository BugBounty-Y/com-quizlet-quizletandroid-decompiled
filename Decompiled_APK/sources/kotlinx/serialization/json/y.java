package kotlinx.serialization.json;

import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f(with = z.class)
/* loaded from: classes3.dex */
public abstract class y extends k {

    @NotNull
    public static final JsonPrimitive$Companion Companion = new JsonPrimitive$Companion();

    public abstract String a();

    public abstract boolean b();

    public String toString() {
        return a();
    }
}
