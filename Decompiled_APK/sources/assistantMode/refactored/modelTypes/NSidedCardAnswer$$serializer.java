package assistantMode.refactored.modelTypes;

import assistantMode.enums.C1451e;
import assistantMode.enums.EnumC1452f;
import assistantMode.enums.t;
import assistantMode.enums.u;
import assistantMode.refactored.modelTypes.NSidedCardAnswer;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;
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
public final class NSidedCardAnswer$$serializer implements D {

    @NotNull
    public static final NSidedCardAnswer$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        NSidedCardAnswer$$serializer nSidedCardAnswer$$serializer = new NSidedCardAnswer$$serializer();
        INSTANCE = nSidedCardAnswer$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("NSidedCardAnswer", nSidedCardAnswer$$serializer, 7);
        pluginGeneratedSerialDescriptor.k(DBAnswerFields.Names.CORRECTNESS, false);
        pluginGeneratedSerialDescriptor.k("round", false);
        pluginGeneratedSerialDescriptor.k("studiableItemId", false);
        pluginGeneratedSerialDescriptor.k("studyModeType", false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        pluginGeneratedSerialDescriptor.k("promptSideIds", false);
        pluginGeneratedSerialDescriptor.k("answerSideIds", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private NSidedCardAnswer$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = NSidedCardAnswer.h;
        KSerializer kSerializer = kSerializerArr[5];
        KSerializer kSerializer2 = kSerializerArr[6];
        P p = P.a;
        return new KSerializer[]{C1451e.f, p, p, t.f, p, kSerializer, kSerializer2};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public NSidedCardAnswer deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = NSidedCardAnswer.h;
        List list = null;
        EnumC1452f enumC1452f = null;
        u uVar = null;
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        int i = 0;
        boolean z = true;
        List list2 = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    enumC1452f = (EnumC1452f) aVarC.z(descriptor2, 0, C1451e.f, enumC1452f);
                    i |= 1;
                    break;
                case 1:
                    j = aVarC.j(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    j2 = aVarC.j(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    uVar = (u) aVarC.z(descriptor2, 3, t.f, uVar);
                    i |= 8;
                    break;
                case 4:
                    j3 = aVarC.j(descriptor2, 4);
                    i |= 16;
                    break;
                case 5:
                    list = (List) aVarC.z(descriptor2, 5, kSerializerArr[5], list);
                    i |= 32;
                    break;
                case 6:
                    list2 = (List) aVarC.z(descriptor2, 6, kSerializerArr[6], list2);
                    i |= 64;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new NSidedCardAnswer(i, enumC1452f, j, j2, uVar, j3, list, list2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull NSidedCardAnswer value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        NSidedCardAnswer.Companion companion = NSidedCardAnswer.Companion;
        bVarC.i(descriptor2, 0, C1451e.f, value.a);
        bVarC.C(descriptor2, 1, value.b);
        bVarC.C(descriptor2, 2, value.c);
        bVarC.i(descriptor2, 3, t.f, value.d);
        bVarC.C(descriptor2, 4, value.e);
        KSerializer[] kSerializerArr = NSidedCardAnswer.h;
        bVarC.i(descriptor2, 5, kSerializerArr[5], value.f);
        bVarC.i(descriptor2, 6, kSerializerArr[6], value.g);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
