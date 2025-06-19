package assistantMode.refactored.types;

import assistantMode.enums.n;
import assistantMode.enums.o;
import assistantMode.refactored.enums.i;
import assistantMode.refactored.enums.j;
import assistantMode.refactored.enums.k;
import assistantMode.refactored.enums.l;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionElement$$serializer;
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
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class AlternativeQuestion$$serializer implements D {

    @NotNull
    public static final AlternativeQuestion$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        AlternativeQuestion$$serializer alternativeQuestion$$serializer = new AlternativeQuestion$$serializer();
        INSTANCE = alternativeQuestion$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("1", alternativeQuestion$$serializer, 10);
        pluginGeneratedSerialDescriptor.k("studiableItemId", false);
        pluginGeneratedSerialDescriptor.k("studiableItemType", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerId", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerType", false);
        pluginGeneratedSerialDescriptor.k("modelVersion", false);
        pluginGeneratedSerialDescriptor.k("predictionTimestamp", false);
        pluginGeneratedSerialDescriptor.k("studiableMetadataCategory", false);
        pluginGeneratedSerialDescriptor.k("studiableMetadataRank", false);
        pluginGeneratedSerialDescriptor.k("prompt", false);
        pluginGeneratedSerialDescriptor.k("answer", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private AlternativeQuestion$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        P p = P.a;
        QuestionElement$$serializer questionElement$$serializer = QuestionElement$$serializer.INSTANCE;
        return new KSerializer[]{p, k.f, p, i.f, q0.a, p, n.f, K.a, questionElement$$serializer, questionElement$$serializer};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public AlternativeQuestion deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        o oVar = null;
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        QuestionElement questionElement = null;
        QuestionElement questionElement2 = null;
        l lVar = null;
        j jVar = null;
        String strR = null;
        boolean z = true;
        int i = 0;
        int iN = 0;
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
                    oVar = (o) aVarC.z(descriptor2, 6, n.f, oVar);
                    i |= 64;
                    break;
                case 7:
                    iN = aVarC.n(descriptor2, 7);
                    i |= 128;
                    break;
                case 8:
                    questionElement = (QuestionElement) aVarC.z(descriptor2, 8, QuestionElement$$serializer.INSTANCE, questionElement);
                    i |= 256;
                    break;
                case 9:
                    questionElement2 = (QuestionElement) aVarC.z(descriptor2, 9, QuestionElement$$serializer.INSTANCE, questionElement2);
                    i |= com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new AlternativeQuestion(i, j, lVar, j2, jVar, strR, j3, oVar, iN, questionElement, questionElement2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull AlternativeQuestion value) {
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
        bVarC.i(descriptor2, 6, n.f, value.g);
        bVarC.l(7, value.h, descriptor2);
        QuestionElement$$serializer questionElement$$serializer = QuestionElement$$serializer.INSTANCE;
        bVarC.i(descriptor2, 8, questionElement$$serializer, value.i);
        bVarC.i(descriptor2, 9, questionElement$$serializer, value.j);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
