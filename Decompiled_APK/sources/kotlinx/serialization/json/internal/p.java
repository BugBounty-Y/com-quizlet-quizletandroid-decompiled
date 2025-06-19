package kotlinx.serialization.json.internal;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes3.dex */
public final class p extends a {
    public final kotlinx.serialization.json.d f;
    public final int g;
    public int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(kotlinx.serialization.json.c json, kotlinx.serialization.json.d value) {
        super(json, null);
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(value, "value");
        this.f = value;
        this.g = value.a.size();
        this.h = -1;
    }

    @Override // kotlinx.serialization.json.internal.a
    public final kotlinx.serialization.json.k E(String tag) throws NumberFormatException {
        Intrinsics.checkNotNullParameter(tag, "tag");
        return this.f.get(Integer.parseInt(tag));
    }

    @Override // kotlinx.serialization.json.internal.a
    public final String R(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return String.valueOf(i);
    }

    @Override // kotlinx.serialization.json.internal.a
    public final kotlinx.serialization.json.k T() {
        return this.f;
    }

    @Override // kotlinx.serialization.encoding.a
    public final int t(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        int i = this.h;
        if (i >= this.g - 1) {
            return -1;
        }
        int i2 = i + 1;
        this.h = i2;
        return i2;
    }
}
