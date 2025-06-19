package assistantMode.refactored.types;

import assistantMode.enums.l;
import assistantMode.enums.m;
import assistantMode.refactored.enums.i;
import assistantMode.refactored.enums.j;
import assistantMode.refactored.enums.k;
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
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class FillInTheBlankQuestionStudiableMetadata$$serializer implements D {

    @NotNull
    public static final FillInTheBlankQuestionStudiableMetadata$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FillInTheBlankQuestionStudiableMetadata$$serializer fillInTheBlankQuestionStudiableMetadata$$serializer = new FillInTheBlankQuestionStudiableMetadata$$serializer();
        INSTANCE = fillInTheBlankQuestionStudiableMetadata$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("2", fillInTheBlankQuestionStudiableMetadata$$serializer, 9);
        pluginGeneratedSerialDescriptor.k("studiableItemId", false);
        pluginGeneratedSerialDescriptor.k("studiableItemType", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerId", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerType", false);
        pluginGeneratedSerialDescriptor.k("modelVersion", false);
        pluginGeneratedSerialDescriptor.k("predictionTimestamp", false);
        pluginGeneratedSerialDescriptor.k("keyphrase", false);
        pluginGeneratedSerialDescriptor.k("keyphraseLocations", false);
        pluginGeneratedSerialDescriptor.k("cardSideLabel", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FillInTheBlankQuestionStudiableMetadata$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = FillInTheBlankQuestionStudiableMetadata.j;
        KSerializer kSerializer = kSerializerArr[6];
        KSerializer kSerializer2 = kSerializerArr[7];
        P p = P.a;
        return new KSerializer[]{p, k.f, p, i.f, q0.a, p, kSerializer, kSerializer2, l.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FillInTheBlankQuestionStudiableMetadata deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = FillInTheBlankQuestionStudiableMetadata.j;
        m mVar = null;
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        assistantMode.refactored.modelTypes.c cVar = null;
        List list = null;
        assistantMode.refactored.enums.l lVar = null;
        j jVar = null;
        String strR = null;
        boolean z = true;
        int i = 0;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    j = aVarC.j(descriptor2, 0);
                    i |= 1;
                    break;
                case 1:
                    lVar = (assistantMode.refactored.enums.l) aVarC.z(descriptor2, 1, k.f, lVar);
                    i |= 2;
                    break;
                case 2:
                    j2 = aVarC.j(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    jVar = (j) aVarC.z(descriptor2, 3, i.f, jVar);
                    i |= 8;
                    break;
                case 4:
                    strR = aVarC.r(descriptor2, 4);
                    i |= 16;
                    break;
                case 5:
                    j3 = aVarC.j(descriptor2, 5);
                    i |= 32;
                    break;
                case 6:
                    cVar = (assistantMode.refactored.modelTypes.c) aVarC.z(descriptor2, 6, kSerializerArr[6], cVar);
                    i |= 64;
                    break;
                case 7:
                    list = (List) aVarC.z(descriptor2, 7, kSerializerArr[7], list);
                    i |= 128;
                    break;
                case 8:
                    mVar = (m) aVarC.z(descriptor2, 8, l.f, mVar);
                    i |= 256;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new FillInTheBlankQuestionStudiableMetadata(i, j, lVar, j2, jVar, strR, j3, cVar, list, mVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FillInTheBlankQuestionStudiableMetadata value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.a);
        bVarC.i(descriptor2, 1, k.f, value.b);
        bVarC.C(descriptor2, 2, value.c);
        bVarC.i(descriptor2, 3, i.f, value.d);
        bVarC.r(descriptor2, 4, value.e);
        bVarC.C(descriptor2, 5, value.f);
        KSerializer[] kSerializerArr = FillInTheBlankQuestionStudiableMetadata.j;
        bVarC.i(descriptor2, 6, kSerializerArr[6], value.g);
        bVarC.i(descriptor2, 7, kSerializerArr[7], value.h);
        boolean zD = bVarC.D(descriptor2);
        m mVar = value.i;
        if (zD || mVar != m.c) {
            bVarC.i(descriptor2, 8, l.f, mVar);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
