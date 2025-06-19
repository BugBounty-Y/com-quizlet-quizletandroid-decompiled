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
public final class FillInTheBlankMultipleChoiceQuestionStudiableMetadata$$serializer implements D {

    @NotNull
    public static final FillInTheBlankMultipleChoiceQuestionStudiableMetadata$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FillInTheBlankMultipleChoiceQuestionStudiableMetadata$$serializer fillInTheBlankMultipleChoiceQuestionStudiableMetadata$$serializer = new FillInTheBlankMultipleChoiceQuestionStudiableMetadata$$serializer();
        INSTANCE = fillInTheBlankMultipleChoiceQuestionStudiableMetadata$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("10", fillInTheBlankMultipleChoiceQuestionStudiableMetadata$$serializer, 10);
        pluginGeneratedSerialDescriptor.k("studiableItemId", false);
        pluginGeneratedSerialDescriptor.k("studiableItemType", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerId", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerType", false);
        pluginGeneratedSerialDescriptor.k("modelVersion", false);
        pluginGeneratedSerialDescriptor.k("predictionTimestamp", false);
        pluginGeneratedSerialDescriptor.k("keyphrase", false);
        pluginGeneratedSerialDescriptor.k("keyphraseLocation", false);
        pluginGeneratedSerialDescriptor.k("cardSideLabel", true);
        pluginGeneratedSerialDescriptor.k("distractors", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FillInTheBlankMultipleChoiceQuestionStudiableMetadata$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = FillInTheBlankMultipleChoiceQuestionStudiableMetadata.k;
        KSerializer kSerializer = kSerializerArr[6];
        KSerializer kSerializer2 = kSerializerArr[9];
        P p = P.a;
        return new KSerializer[]{p, k.f, p, i.f, q0.a, p, kSerializer, FillInTheBlankKeyphraseLocation$$serializer.INSTANCE, l.f, kSerializer2};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FillInTheBlankMultipleChoiceQuestionStudiableMetadata deserialize(@NotNull Decoder decoder) {
        KSerializer[] kSerializerArr;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr2 = FillInTheBlankMultipleChoiceQuestionStudiableMetadata.k;
        assistantMode.refactored.modelTypes.c cVar = null;
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        FillInTheBlankKeyphraseLocation fillInTheBlankKeyphraseLocation = null;
        m mVar = null;
        List list = null;
        assistantMode.refactored.enums.l lVar = null;
        j jVar = null;
        String strR = null;
        int i = 0;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    kSerializerArr = kSerializerArr2;
                    z = false;
                    break;
                case 0:
                    kSerializerArr = kSerializerArr2;
                    j = aVarC.j(descriptor2, 0);
                    i |= 1;
                    break;
                case 1:
                    kSerializerArr = kSerializerArr2;
                    lVar = (assistantMode.refactored.enums.l) aVarC.z(descriptor2, 1, k.f, lVar);
                    i |= 2;
                    break;
                case 2:
                    kSerializerArr = kSerializerArr2;
                    j2 = aVarC.j(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    kSerializerArr = kSerializerArr2;
                    jVar = (j) aVarC.z(descriptor2, 3, i.f, jVar);
                    i |= 8;
                    break;
                case 4:
                    kSerializerArr = kSerializerArr2;
                    strR = aVarC.r(descriptor2, 4);
                    i |= 16;
                    break;
                case 5:
                    kSerializerArr = kSerializerArr2;
                    j3 = aVarC.j(descriptor2, 5);
                    i |= 32;
                    break;
                case 6:
                    kSerializerArr = kSerializerArr2;
                    cVar = (assistantMode.refactored.modelTypes.c) aVarC.z(descriptor2, 6, kSerializerArr[6], cVar);
                    i |= 64;
                    break;
                case 7:
                    kSerializerArr = kSerializerArr2;
                    fillInTheBlankKeyphraseLocation = (FillInTheBlankKeyphraseLocation) aVarC.z(descriptor2, 7, FillInTheBlankKeyphraseLocation$$serializer.INSTANCE, fillInTheBlankKeyphraseLocation);
                    i |= 128;
                    break;
                case 8:
                    kSerializerArr = kSerializerArr2;
                    mVar = (m) aVarC.z(descriptor2, 8, l.f, mVar);
                    i |= 256;
                    break;
                case 9:
                    kSerializerArr = kSerializerArr2;
                    list = (List) aVarC.z(descriptor2, 9, kSerializerArr[9], list);
                    i |= com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
            kSerializerArr2 = kSerializerArr;
        }
        aVarC.b(descriptor2);
        return new FillInTheBlankMultipleChoiceQuestionStudiableMetadata(i, j, lVar, j2, jVar, strR, j3, cVar, fillInTheBlankKeyphraseLocation, mVar, list);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FillInTheBlankMultipleChoiceQuestionStudiableMetadata value) {
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
        KSerializer[] kSerializerArr = FillInTheBlankMultipleChoiceQuestionStudiableMetadata.k;
        bVarC.i(descriptor2, 6, kSerializerArr[6], value.g);
        bVarC.i(descriptor2, 7, FillInTheBlankKeyphraseLocation$$serializer.INSTANCE, value.h);
        boolean zD = bVarC.D(descriptor2);
        m mVar = value.i;
        if (zD || mVar != m.c) {
            bVarC.i(descriptor2, 8, l.f, mVar);
        }
        bVarC.i(descriptor2, 9, kSerializerArr[9], value.j);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
