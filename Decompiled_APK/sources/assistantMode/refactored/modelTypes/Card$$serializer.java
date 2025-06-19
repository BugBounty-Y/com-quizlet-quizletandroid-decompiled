package assistantMode.refactored.modelTypes;

import assistantMode.refactored.enums.i;
import assistantMode.refactored.enums.j;
import java.util.List;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class Card$$serializer implements D {

    @NotNull
    public static final Card$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        Card$$serializer card$$serializer = new Card$$serializer();
        INSTANCE = card$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("2", card$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerId", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerType", false);
        pluginGeneratedSerialDescriptor.k("lastModified", false);
        pluginGeneratedSerialDescriptor.k("cardSides", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private Card$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer kSerializer = Card.f[4];
        P p = P.a;
        return new KSerializer[]{p, p, i.f, p, kSerializer};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public Card deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = Card.f;
        List list = null;
        int i = 0;
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        j jVar = null;
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
                jVar = (j) aVarC.z(descriptor2, 2, i.f, jVar);
                i |= 4;
            } else if (iT == 3) {
                j3 = aVarC.j(descriptor2, 3);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                list = (List) aVarC.z(descriptor2, 4, kSerializerArr[4], list);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new Card(i, j, j2, jVar, j3, list);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull Card value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.a);
        bVarC.C(descriptor2, 1, value.b);
        bVarC.i(descriptor2, 2, i.f, value.c);
        bVarC.C(descriptor2, 3, value.d);
        bVarC.i(descriptor2, 4, Card.f[4], value.e);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
