package kotlinx.serialization.internal;

import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public abstract class g0 extends AbstractC5064s {
    public final f0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g0(KSerializer primitiveSerializer) {
        super(primitiveSerializer);
        Intrinsics.checkNotNullParameter(primitiveSerializer, "primitiveSerializer");
        this.b = new f0(primitiveSerializer.getDescriptor());
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object a() {
        return (AbstractC5051e0) g(j());
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int b(Object obj) {
        AbstractC5051e0 abstractC5051e0 = (AbstractC5051e0) obj;
        Intrinsics.checkNotNullParameter(abstractC5051e0, "<this>");
        return abstractC5051e0.d();
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Iterator c(Object obj) {
        throw new IllegalStateException("This method lead to boxing and must not be used, use writeContents instead");
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a, kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        return e(decoder);
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        return this.b;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object h(Object obj) {
        AbstractC5051e0 abstractC5051e0 = (AbstractC5051e0) obj;
        Intrinsics.checkNotNullParameter(abstractC5051e0, "<this>");
        return abstractC5051e0.a();
    }

    @Override // kotlinx.serialization.internal.AbstractC5064s
    public final void i(int i, Object obj, Object obj2) {
        Intrinsics.checkNotNullParameter((AbstractC5051e0) obj, "<this>");
        throw new IllegalStateException("This method lead to boxing and must not be used, use Builder.append instead");
    }

    public abstract Object j();

    public abstract void k(kotlinx.serialization.encoding.b bVar, Object obj, int i);

    @Override // kotlinx.serialization.internal.AbstractC5064s, kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        int iD = d(obj);
        f0 f0Var = this.b;
        kotlinx.serialization.encoding.b bVarZ = encoder.z(f0Var);
        k(bVarZ, obj, iD);
        bVarZ.b(f0Var);
    }
}
