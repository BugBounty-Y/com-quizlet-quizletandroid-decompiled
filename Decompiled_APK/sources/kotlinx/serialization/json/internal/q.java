package kotlinx.serialization.json.internal;

import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes3.dex */
public final class q extends o {
    public final kotlinx.serialization.json.v j;
    public final List k;
    public final int l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(kotlinx.serialization.json.c json, kotlinx.serialization.json.v value) {
        super(json, value, (String) null, 12);
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(value, "value");
        this.j = value;
        List listW0 = CollectionsKt.w0(value.a.keySet());
        this.k = listW0;
        this.l = listW0.size() * 2;
        this.m = -1;
    }

    @Override // kotlinx.serialization.json.internal.o, kotlinx.serialization.json.internal.a
    public final kotlinx.serialization.json.k E(String tag) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        return this.m % 2 == 0 ? kotlinx.serialization.json.l.c(tag) : (kotlinx.serialization.json.k) V.d(tag, this.j);
    }

    @Override // kotlinx.serialization.json.internal.o, kotlinx.serialization.json.internal.a
    public final String R(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return (String) this.k.get(i / 2);
    }

    @Override // kotlinx.serialization.json.internal.o, kotlinx.serialization.json.internal.a
    public final kotlinx.serialization.json.k T() {
        return this.j;
    }

    @Override // kotlinx.serialization.json.internal.o
    /* renamed from: Y */
    public final kotlinx.serialization.json.v T() {
        return this.j;
    }

    @Override // kotlinx.serialization.json.internal.o, kotlinx.serialization.json.internal.a, kotlinx.serialization.encoding.a
    public final void b(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
    }

    @Override // kotlinx.serialization.json.internal.o, kotlinx.serialization.encoding.a
    public final int t(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        int i = this.m;
        if (i >= this.l - 1) {
            return -1;
        }
        int i2 = i + 1;
        this.m = i2;
        return i2;
    }
}
