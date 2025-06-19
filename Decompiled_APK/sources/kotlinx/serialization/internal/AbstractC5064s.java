package kotlinx.serialization.internal;

import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Encoder;

/* renamed from: kotlinx.serialization.internal.s, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC5064s extends AbstractC5042a {
    public final KSerializer a;

    public AbstractC5064s(KSerializer kSerializer) {
        this.a = kSerializer;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public void f(kotlinx.serialization.encoding.a decoder, int i, Object obj) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        i(i, obj, decoder.z(getDescriptor(), i, this.a, null));
    }

    public abstract void i(int i, Object obj, Object obj2);

    @Override // kotlinx.serialization.KSerializer
    public void serialize(Encoder encoder, Object obj) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        int iD = d(obj);
        SerialDescriptor descriptor = getDescriptor();
        kotlinx.serialization.encoding.b bVarZ = encoder.z(descriptor);
        Iterator itC = c(obj);
        for (int i = 0; i < iD; i++) {
            bVarZ.i(getDescriptor(), i, this.a, itC.next());
        }
        bVarZ.b(descriptor);
    }
}
