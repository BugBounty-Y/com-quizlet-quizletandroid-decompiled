package kotlinx.serialization.internal;

import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes3.dex */
public final class G extends PluginGeneratedSerialDescriptor {
    public final boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(String name, H generatedSerializer) {
        super(name, generatedSerializer, 1);
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(generatedSerializer, "generatedSerializer");
        this.l = true;
    }

    /* JADX WARN: Type inference failed for: r2v3, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r6v3, types: [java.lang.Object, kotlin.k] */
    @Override // kotlinx.serialization.internal.PluginGeneratedSerialDescriptor
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof G) {
            SerialDescriptor serialDescriptor = (SerialDescriptor) obj;
            if (Intrinsics.b(this.a, serialDescriptor.a())) {
                G g = (G) obj;
                if (g.l && Arrays.equals((SerialDescriptor[]) this.j.getValue(), (SerialDescriptor[]) g.j.getValue())) {
                    int iF = serialDescriptor.f();
                    int i = this.c;
                    if (i == iF) {
                        for (int i2 = 0; i2 < i; i2++) {
                            if (Intrinsics.b(i(i2).a(), serialDescriptor.i(i2).a()) && Intrinsics.b(i(i2).e(), serialDescriptor.i(i2).e())) {
                            }
                        }
                        return true;
                    }
                }
            }
        }
        return false;
    }

    @Override // kotlinx.serialization.internal.PluginGeneratedSerialDescriptor
    public final int hashCode() {
        return super.hashCode() * 31;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final boolean isInline() {
        return this.l;
    }
}
