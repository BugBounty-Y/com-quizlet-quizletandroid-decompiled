package kotlinx.serialization.json;

import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f(with = u.class)
@Metadata
/* loaded from: classes3.dex */
public final class JsonNull extends y {

    @NotNull
    public static final JsonNull INSTANCE = new JsonNull();

    @Override // kotlinx.serialization.json.y
    public final String a() {
        return "null";
    }

    @Override // kotlinx.serialization.json.y
    public final boolean b() {
        return false;
    }

    @NotNull
    public final KSerializer serializer() {
        return u.a;
    }
}
