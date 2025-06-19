package com.quizlet.shared.models.api.srs;

import assistantMode.enums.l;
import assistantMode.enums.m;
import java.util.List;
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
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class SrsResponse$$serializer implements D {

    @NotNull
    public static final SrsResponse$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        SrsResponse$$serializer srsResponse$$serializer = new SrsResponse$$serializer();
        INSTANCE = srsResponse$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.srs.SrsResponse", srsResponse$$serializer, 7);
        pluginGeneratedSerialDescriptor.k("studiableContainerProgress", false);
        pluginGeneratedSerialDescriptor.k("apiVersion", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerPromptSide", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerScores", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerTotalItemsDue", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerTotalItemsNotDue", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerTotalItemsNotStudied", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private SrsResponse$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = SrsResponse.h;
        KSerializer kSerializer = kSerializerArr[0];
        KSerializer kSerializer2 = kSerializerArr[3];
        K k = K.a;
        return new KSerializer[]{kSerializer, q0.a, l.f, kSerializer2, k, k, k};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SrsResponse deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = SrsResponse.h;
        int i = 0;
        int iN = 0;
        int iN2 = 0;
        int iN3 = 0;
        List list = null;
        String strR = null;
        m mVar = null;
        List list2 = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    list = (List) aVarC.z(descriptor2, 0, kSerializerArr[0], list);
                    i |= 1;
                    break;
                case 1:
                    strR = aVarC.r(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    mVar = (m) aVarC.z(descriptor2, 2, l.f, mVar);
                    i |= 4;
                    break;
                case 3:
                    list2 = (List) aVarC.z(descriptor2, 3, kSerializerArr[3], list2);
                    i |= 8;
                    break;
                case 4:
                    iN = aVarC.n(descriptor2, 4);
                    i |= 16;
                    break;
                case 5:
                    iN2 = aVarC.n(descriptor2, 5);
                    i |= 32;
                    break;
                case 6:
                    iN3 = aVarC.n(descriptor2, 6);
                    i |= 64;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new SrsResponse(i, list, strR, mVar, list2, iN, iN2, iN3);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull SrsResponse value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        KSerializer[] kSerializerArr = SrsResponse.h;
        bVarC.i(descriptor2, 0, kSerializerArr[0], value.a);
        bVarC.r(descriptor2, 1, value.b);
        bVarC.i(descriptor2, 2, l.f, value.c);
        bVarC.i(descriptor2, 3, kSerializerArr[3], value.d);
        bVarC.l(4, value.e, descriptor2);
        bVarC.l(5, value.f, descriptor2);
        bVarC.l(6, value.g, descriptor2);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
