package kotlinx.serialization;

import androidx.camera.camera2.internal.p0;
import com.google.android.gms.internal.mlkit_vision_camera.T1;
import java.util.List;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.v;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.descriptors.h;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.AbstractC5047c0;

/* loaded from: classes3.dex */
public final class a implements KSerializer {
    public final /* synthetic */ int a = 0;
    public final KSerializer b;
    public final Object c;
    public final Object d;
    public final SerialDescriptor e;

    public a(C4950i context, KSerializer kSerializer, KSerializer[] typeArgumentsSerializers) {
        Intrinsics.checkNotNullParameter(context, "serializableClass");
        Intrinsics.checkNotNullParameter(typeArgumentsSerializers, "typeArgumentsSerializers");
        this.c = context;
        this.b = kSerializer;
        this.d = C4930v.c(typeArgumentsSerializers);
        kotlinx.serialization.descriptors.g gVarG = T1.g("kotlinx.serialization.ContextualSerializer", h.b, new SerialDescriptor[0], new com.quizlet.ui.compose.modifiers.b(this, 14));
        Intrinsics.checkNotNullParameter(gVarG, "<this>");
        Intrinsics.checkNotNullParameter(context, "context");
        this.e = new kotlinx.serialization.descriptors.b(gVarG, context);
    }

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(decoder, "decoder");
                p0 p0VarA = decoder.a();
                C4950i c4950i = (C4950i) this.c;
                KSerializer kSerializerI = p0VarA.i(c4950i, (List) this.d);
                if (kSerializerI != null || (kSerializerI = this.b) != null) {
                    return decoder.u(kSerializerI);
                }
                AbstractC5047c0.j(c4950i);
                throw null;
            default:
                Intrinsics.checkNotNullParameter(decoder, "decoder");
                kotlinx.serialization.descriptors.g gVar = (kotlinx.serialization.descriptors.g) this.e;
                kotlinx.serialization.encoding.a aVarC = decoder.c(gVar);
                Object obj = AbstractC5047c0.c;
                Object objZ = obj;
                Object objZ2 = objZ;
                Object objZ3 = objZ2;
                while (true) {
                    int iT = aVarC.t(gVar);
                    if (iT == -1) {
                        aVarC.b(gVar);
                        if (objZ == obj) {
                            throw new SerializationException("Element 'first' is missing");
                        }
                        if (objZ2 == obj) {
                            throw new SerializationException("Element 'second' is missing");
                        }
                        if (objZ3 != obj) {
                            return new v(objZ, objZ2, objZ3);
                        }
                        throw new SerializationException("Element 'third' is missing");
                    }
                    if (iT == 0) {
                        objZ = aVarC.z(gVar, 0, this.b, null);
                    } else if (iT == 1) {
                        objZ2 = aVarC.z(gVar, 1, (KSerializer) this.c, null);
                    } else {
                        if (iT != 2) {
                            throw new SerializationException(android.support.v4.media.session.a.f(iT, "Unexpected index "));
                        }
                        objZ3 = aVarC.z(gVar, 2, (KSerializer) this.d, null);
                    }
                }
        }
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        switch (this.a) {
            case 0:
                return (kotlinx.serialization.descriptors.b) this.e;
            default:
                return (kotlinx.serialization.descriptors.g) this.e;
        }
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object value) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(encoder, "encoder");
                Intrinsics.checkNotNullParameter(value, "value");
                p0 p0VarA = encoder.a();
                C4950i c4950i = (C4950i) this.c;
                KSerializer kSerializerI = p0VarA.i(c4950i, (List) this.d);
                if (kSerializerI == null && (kSerializerI = this.b) == null) {
                    AbstractC5047c0.j(c4950i);
                    throw null;
                }
                encoder.y(kSerializerI, value);
                return;
            default:
                v value2 = (v) value;
                Intrinsics.checkNotNullParameter(encoder, "encoder");
                Intrinsics.checkNotNullParameter(value2, "value");
                kotlinx.serialization.descriptors.g gVar = (kotlinx.serialization.descriptors.g) this.e;
                kotlinx.serialization.encoding.b bVarC = encoder.c(gVar);
                bVarC.i(gVar, 0, this.b, value2.a);
                bVarC.i(gVar, 1, (KSerializer) this.c, value2.b);
                bVarC.i(gVar, 2, (KSerializer) this.d, value2.c);
                bVarC.b(gVar);
                return;
        }
    }

    public a(KSerializer aSerializer, KSerializer bSerializer, KSerializer cSerializer) {
        Intrinsics.checkNotNullParameter(aSerializer, "aSerializer");
        Intrinsics.checkNotNullParameter(bSerializer, "bSerializer");
        Intrinsics.checkNotNullParameter(cSerializer, "cSerializer");
        this.b = aSerializer;
        this.c = bSerializer;
        this.d = cSerializer;
        this.e = T1.f("kotlin.Triple", new SerialDescriptor[0], new com.quizlet.ui.compose.modifiers.b(this, 18));
    }
}
