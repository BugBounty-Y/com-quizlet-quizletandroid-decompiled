package assistantMode.refactored.types;

import assistantMode.refactored.enums.i;
import assistantMode.refactored.enums.j;
import assistantMode.refactored.enums.k;
import assistantMode.refactored.enums.l;
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
public final class CardSideQuestionTypeRecommendation$$serializer implements D {

    @NotNull
    public static final CardSideQuestionTypeRecommendation$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        CardSideQuestionTypeRecommendation$$serializer cardSideQuestionTypeRecommendation$$serializer = new CardSideQuestionTypeRecommendation$$serializer();
        INSTANCE = cardSideQuestionTypeRecommendation$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("5", cardSideQuestionTypeRecommendation$$serializer, 9);
        pluginGeneratedSerialDescriptor.k("studiableItemId", false);
        pluginGeneratedSerialDescriptor.k("studiableItemType", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerId", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerType", false);
        pluginGeneratedSerialDescriptor.k("modelVersion", false);
        pluginGeneratedSerialDescriptor.k("predictionTimestamp", false);
        pluginGeneratedSerialDescriptor.k("multipleChoice", false);
        pluginGeneratedSerialDescriptor.k("written", false);
        pluginGeneratedSerialDescriptor.k("revealSelfAssessment", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private CardSideQuestionTypeRecommendation$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        P p = P.a;
        AnswerSidePriorities$$serializer answerSidePriorities$$serializer = AnswerSidePriorities$$serializer.INSTANCE;
        return new KSerializer[]{p, k.f, p, i.f, q0.a, p, answerSidePriorities$$serializer, answerSidePriorities$$serializer, answerSidePriorities$$serializer};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public CardSideQuestionTypeRecommendation deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        AnswerSidePriorities answerSidePriorities = null;
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        AnswerSidePriorities answerSidePriorities2 = null;
        AnswerSidePriorities answerSidePriorities3 = null;
        l lVar = null;
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
                    lVar = (l) aVarC.z(descriptor2, 1, k.f, lVar);
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
                    answerSidePriorities2 = (AnswerSidePriorities) aVarC.z(descriptor2, 6, AnswerSidePriorities$$serializer.INSTANCE, answerSidePriorities2);
                    i |= 64;
                    break;
                case 7:
                    answerSidePriorities3 = (AnswerSidePriorities) aVarC.z(descriptor2, 7, AnswerSidePriorities$$serializer.INSTANCE, answerSidePriorities3);
                    i |= 128;
                    break;
                case 8:
                    answerSidePriorities = (AnswerSidePriorities) aVarC.z(descriptor2, 8, AnswerSidePriorities$$serializer.INSTANCE, answerSidePriorities);
                    i |= 256;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new CardSideQuestionTypeRecommendation(i, j, lVar, j2, jVar, strR, j3, answerSidePriorities2, answerSidePriorities3, answerSidePriorities);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull CardSideQuestionTypeRecommendation value) {
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
        AnswerSidePriorities$$serializer answerSidePriorities$$serializer = AnswerSidePriorities$$serializer.INSTANCE;
        bVarC.i(descriptor2, 6, answerSidePriorities$$serializer, value.g);
        bVarC.i(descriptor2, 7, answerSidePriorities$$serializer, value.h);
        bVarC.i(descriptor2, 8, answerSidePriorities$$serializer, value.i);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
