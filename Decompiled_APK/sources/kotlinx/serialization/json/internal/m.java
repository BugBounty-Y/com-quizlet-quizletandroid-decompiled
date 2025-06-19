package kotlinx.serialization.json.internal;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes3.dex */
public final class m extends a {
    public final kotlinx.serialization.json.k f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(kotlinx.serialization.json.c json, kotlinx.serialization.json.k value, String str) {
        super(json, str);
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(value, "value");
        this.f = value;
        this.a.add("primitive");
    }

    @Override // kotlinx.serialization.json.internal.a
    public final kotlinx.serialization.json.k E(String tag) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        if (tag == "primitive") {
            return this.f;
        }
        throw new IllegalArgumentException("This input can only handle primitives with 'primitive' tag");
    }

    @Override // kotlinx.serialization.json.internal.a
    public final kotlinx.serialization.json.k T() {
        return this.f;
    }

    @Override // kotlinx.serialization.encoding.a
    public final int t(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return 0;
    }
}
