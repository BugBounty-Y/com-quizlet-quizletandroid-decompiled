package kotlinx.serialization.descriptors;

import com.google.android.gms.internal.mlkit_vision_camera.U1;
import java.util.List;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements SerialDescriptor {
    public final g a;
    public final kotlin.reflect.c b;
    public final String c;

    public b(g original, kotlin.reflect.c kClass) {
        Intrinsics.checkNotNullParameter(original, "original");
        Intrinsics.checkNotNullParameter(kClass, "kClass");
        this.a = original;
        this.b = kClass;
        this.c = original.a + '<' + ((C4950i) kClass).f() + '>';
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final String a() {
        return this.c;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final boolean c() {
        return false;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final int d(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        return this.a.d(name);
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final U1 e() {
        return this.a.b;
    }

    public final boolean equals(Object obj) {
        b bVar = obj instanceof b ? (b) obj : null;
        return bVar != null && this.a.equals(bVar.a) && Intrinsics.b(bVar.b, this.b);
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final int f() {
        return this.a.c;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final String g(int i) {
        return this.a.f[i];
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final List getAnnotations() {
        return this.a.d;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final List h(int i) {
        return this.a.h[i];
    }

    public final int hashCode() {
        return this.c.hashCode() + (((C4950i) this.b).hashCode() * 31);
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final SerialDescriptor i(int i) {
        return this.a.g[i];
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final boolean isInline() {
        return false;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final boolean j(int i) {
        return this.a.i[i];
    }

    public final String toString() {
        return "ContextDescriptor(kClass: " + this.b + ", original: " + this.a + ')';
    }
}
