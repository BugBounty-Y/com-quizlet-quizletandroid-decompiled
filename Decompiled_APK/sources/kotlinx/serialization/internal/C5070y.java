package kotlinx.serialization.internal;

import com.google.android.gms.internal.mlkit_vision_camera.U1;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* renamed from: kotlinx.serialization.internal.y, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5070y extends PluginGeneratedSerialDescriptor {
    public final kotlinx.serialization.descriptors.i l;
    public final kotlin.u m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5070y(String name, int i) {
        super(name, null, i);
        Intrinsics.checkNotNullParameter(name, "name");
        this.l = kotlinx.serialization.descriptors.i.b;
        this.m = kotlin.l.b(new com.quizlet.assembly.compose.cards.a(i, name, this));
    }

    @Override // kotlinx.serialization.internal.PluginGeneratedSerialDescriptor, kotlinx.serialization.descriptors.SerialDescriptor
    public final U1 e() {
        return this.l;
    }

    @Override // kotlinx.serialization.internal.PluginGeneratedSerialDescriptor
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof SerialDescriptor)) {
            return false;
        }
        SerialDescriptor serialDescriptor = (SerialDescriptor) obj;
        if (serialDescriptor.e() != kotlinx.serialization.descriptors.i.b) {
            return false;
        }
        return Intrinsics.b(this.a, serialDescriptor.a()) && Intrinsics.b(AbstractC5047c0.b(this), AbstractC5047c0.b(serialDescriptor));
    }

    @Override // kotlinx.serialization.internal.PluginGeneratedSerialDescriptor
    public final int hashCode() {
        int iHashCode = this.a.hashCode();
        Intrinsics.checkNotNullParameter(this, "<this>");
        androidx.collection.Y y = new androidx.collection.Y(this);
        int iHashCode2 = 1;
        while (y.hasNext()) {
            int i = iHashCode2 * 31;
            String str = (String) y.next();
            iHashCode2 = i + (str != null ? str.hashCode() : 0);
        }
        return (iHashCode * 31) + iHashCode2;
    }

    @Override // kotlinx.serialization.internal.PluginGeneratedSerialDescriptor, kotlinx.serialization.descriptors.SerialDescriptor
    public final SerialDescriptor i(int i) {
        return ((SerialDescriptor[]) this.m.getValue())[i];
    }

    @Override // kotlinx.serialization.internal.PluginGeneratedSerialDescriptor
    public final String toString() {
        Intrinsics.checkNotNullParameter(this, "<this>");
        return CollectionsKt.S(new kotlin.collections.N(this, 2), ", ", androidx.compose.animation.d0.r(new StringBuilder(), this.a, '('), ")", null, 56);
    }
}
