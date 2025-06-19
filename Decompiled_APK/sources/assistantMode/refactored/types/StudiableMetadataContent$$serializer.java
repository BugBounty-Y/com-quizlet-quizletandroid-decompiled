package assistantMode.refactored.types;

import assistantMode.enums.p;
import assistantMode.enums.q;
import assistantMode.refactored.types.StudiableMetadataContent;
import java.util.List;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.collections.K;
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
public final class StudiableMetadataContent$$serializer implements D {

    @NotNull
    public static final StudiableMetadataContent$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        StudiableMetadataContent$$serializer studiableMetadataContent$$serializer = new StudiableMetadataContent$$serializer();
        INSTANCE = studiableMetadataContent$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.StudiableMetadataContent", studiableMetadataContent$$serializer, 2);
        pluginGeneratedSerialDescriptor.k("studiableMetadata", true);
        pluginGeneratedSerialDescriptor.k("studiableMetadataStatus", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private StudiableMetadataContent$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{StudiableMetadataContent.c[0], p.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public StudiableMetadataContent deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = StudiableMetadataContent.c;
        List list = null;
        boolean z = true;
        int i = 0;
        q qVar = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                list = (List) aVarC.z(descriptor2, 0, kSerializerArr[0], list);
                i |= 1;
            } else {
                if (iT != 1) {
                    throw new UnknownFieldException(iT);
                }
                qVar = (q) aVarC.z(descriptor2, 1, p.f, qVar);
                i |= 2;
            }
        }
        aVarC.b(descriptor2);
        return new StudiableMetadataContent(i, list, qVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull StudiableMetadataContent value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        StudiableMetadataContent.Companion companion = StudiableMetadataContent.Companion;
        if (bVarC.D(descriptor2) || !Intrinsics.b(value.a, K.a)) {
            bVarC.i(descriptor2, 0, StudiableMetadataContent.c[0], value.a);
        }
        if (bVarC.D(descriptor2) || value.b != q.d) {
            bVarC.i(descriptor2, 1, p.f, value.b);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
