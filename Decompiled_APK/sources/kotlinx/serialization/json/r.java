package kotlinx.serialization.json;

import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes3.dex */
public final class r extends y {
    public final boolean a;
    public final SerialDescriptor b;
    public final String c;

    public r(Serializable body, boolean z, SerialDescriptor serialDescriptor) {
        Intrinsics.checkNotNullParameter(body, "body");
        this.a = z;
        this.b = serialDescriptor;
        this.c = body.toString();
        if (serialDescriptor != null && !serialDescriptor.isInline()) {
            throw new IllegalArgumentException("Failed requirement.");
        }
    }

    @Override // kotlinx.serialization.json.y
    public final String a() {
        return this.c;
    }

    @Override // kotlinx.serialization.json.y
    public final boolean b() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || r.class != obj.getClass()) {
            return false;
        }
        r rVar = (r) obj;
        return this.a == rVar.a && Intrinsics.b(this.c, rVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + (Boolean.hashCode(this.a) * 31);
    }

    @Override // kotlinx.serialization.json.y
    public final String toString() {
        boolean z = this.a;
        String str = this.c;
        if (!z) {
            return str;
        }
        StringBuilder sb = new StringBuilder();
        kotlinx.serialization.json.internal.x.a(str, sb);
        return sb.toString();
    }
}
