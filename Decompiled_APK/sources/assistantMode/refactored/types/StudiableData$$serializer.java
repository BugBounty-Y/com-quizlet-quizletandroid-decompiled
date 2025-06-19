package assistantMode.refactored.types;

import java.util.List;
import java.util.Map;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class StudiableData$$serializer implements D {

    @NotNull
    public static final StudiableData$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        StudiableData$$serializer studiableData$$serializer = new StudiableData$$serializer();
        INSTANCE = studiableData$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.StudiableData", studiableData$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("studiableItems", false);
        pluginGeneratedSerialDescriptor.k("setIdToDiagramImage", true);
        pluginGeneratedSerialDescriptor.k("studiableMetadataByType", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private StudiableData$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = StudiableData.d;
        return new KSerializer[]{kSerializerArr[0], kSerializerArr[1], kSerializerArr[2]};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public StudiableData deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = StudiableData.d;
        List list = null;
        boolean z = true;
        int i = 0;
        Map map = null;
        Map map2 = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                list = (List) aVarC.z(descriptor2, 0, kSerializerArr[0], list);
                i |= 1;
            } else if (iT == 1) {
                map = (Map) aVarC.z(descriptor2, 1, kSerializerArr[1], map);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                map2 = (Map) aVarC.z(descriptor2, 2, kSerializerArr[2], map2);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new StudiableData(i, list, map, map2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull StudiableData value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        KSerializer[] kSerializerArr = StudiableData.d;
        bVarC.i(descriptor2, 0, kSerializerArr[0], value.a);
        boolean zD = bVarC.D(descriptor2);
        Map map = value.b;
        if (zD || !Intrinsics.b(map, V.c())) {
            bVarC.i(descriptor2, 1, kSerializerArr[1], map);
        }
        boolean zD2 = bVarC.D(descriptor2);
        Map map2 = value.c;
        if (zD2 || !Intrinsics.b(map2, V.c())) {
            bVarC.i(descriptor2, 2, kSerializerArr[2], map2);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
