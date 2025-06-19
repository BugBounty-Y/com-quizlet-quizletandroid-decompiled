package kotlinx.serialization.internal;

import com.google.android.gms.internal.mlkit_vision_camera.U1;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes3.dex */
public abstract class M implements SerialDescriptor {
    public final SerialDescriptor a;

    public M(SerialDescriptor serialDescriptor) {
        this.a = serialDescriptor;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final int d(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        Integer intOrNull = StringsKt.toIntOrNull(name);
        if (intOrNull != null) {
            return intOrNull.intValue();
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.k(name, " is not a valid list index"));
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final U1 e() {
        return kotlinx.serialization.descriptors.j.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof M)) {
            return false;
        }
        M m = (M) obj;
        return Intrinsics.b(this.a, m.a) && Intrinsics.b(a(), m.a());
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final int f() {
        return 1;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final String g(int i) {
        return String.valueOf(i);
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final List h(int i) {
        if (i >= 0) {
            return kotlin.collections.K.a;
        }
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Illegal index ", ", ");
        sbV.append(a());
        sbV.append(" expects only non-negative indices");
        throw new IllegalArgumentException(sbV.toString().toString());
    }

    public final int hashCode() {
        return a().hashCode() + (this.a.hashCode() * 31);
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final SerialDescriptor i(int i) {
        if (i >= 0) {
            return this.a;
        }
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Illegal index ", ", ");
        sbV.append(a());
        sbV.append(" expects only non-negative indices");
        throw new IllegalArgumentException(sbV.toString().toString());
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final boolean j(int i) {
        if (i >= 0) {
            return false;
        }
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Illegal index ", ", ");
        sbV.append(a());
        sbV.append(" expects only non-negative indices");
        throw new IllegalArgumentException(sbV.toString().toString());
    }

    public final String toString() {
        return a() + '(' + this.a + ')';
    }
}
