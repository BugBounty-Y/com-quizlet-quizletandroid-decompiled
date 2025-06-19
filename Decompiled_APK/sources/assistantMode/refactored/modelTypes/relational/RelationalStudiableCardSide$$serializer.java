package assistantMode.refactored.modelTypes.relational;

import assistantMode.enums.l;
import assistantMode.enums.m;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.encoding.a;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class RelationalStudiableCardSide$$serializer implements D {

    @NotNull
    public static final RelationalStudiableCardSide$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RelationalStudiableCardSide$$serializer relationalStudiableCardSide$$serializer = new RelationalStudiableCardSide$$serializer();
        INSTANCE = relationalStudiableCardSide$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.modelTypes.relational.RelationalStudiableCardSide", relationalStudiableCardSide$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("studiableItemId", false);
        pluginGeneratedSerialDescriptor.k("label", false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        pluginGeneratedSerialDescriptor.k("lastModified", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RelationalStudiableCardSide$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        P p = P.a;
        return new KSerializer[]{p, p, l.f, p, p};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RelationalStudiableCardSide deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        int i = 0;
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        long j4 = 0;
        m mVar = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                j = aVarC.j(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                j2 = aVarC.j(descriptor2, 1);
                i |= 2;
            } else if (iT == 2) {
                mVar = (m) aVarC.z(descriptor2, 2, l.f, mVar);
                i |= 4;
            } else if (iT == 3) {
                j3 = aVarC.j(descriptor2, 3);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                j4 = aVarC.j(descriptor2, 4);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new RelationalStudiableCardSide(i, j, j2, mVar, j3, j4);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RelationalStudiableCardSide value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.a);
        bVarC.C(descriptor2, 1, value.b);
        bVarC.i(descriptor2, 2, l.f, value.c);
        bVarC.C(descriptor2, 3, value.d);
        bVarC.C(descriptor2, 4, value.e);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
