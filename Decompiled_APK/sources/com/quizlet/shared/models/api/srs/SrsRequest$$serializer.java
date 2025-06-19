package com.quizlet.shared.models.api.srs;

import assistantMode.refactored.enums.i;
import assistantMode.refactored.enums.j;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.shared.models.api.srs.SrsRequest;
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
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class SrsRequest$$serializer implements D {

    @NotNull
    public static final SrsRequest$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        SrsRequest$$serializer srsRequest$$serializer = new SrsRequest$$serializer();
        INSTANCE = srsRequest$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.srs.SrsRequest", srsRequest$$serializer, 6);
        pluginGeneratedSerialDescriptor.k("personId", true);
        pluginGeneratedSerialDescriptor.k("studiableContainerId", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerType", false);
        pluginGeneratedSerialDescriptor.k("personTimezone", true);
        pluginGeneratedSerialDescriptor.k("personTestDate", true);
        pluginGeneratedSerialDescriptor.k("clientLatestAnswers", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private SrsRequest$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = SrsRequest.g;
        P p = P.a;
        return new KSerializer[]{R1.e(p), p, i.f, R1.e(q0.a), R1.e(p), R1.e(kSerializerArr[5])};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SrsRequest deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = SrsRequest.g;
        List list = null;
        int i = 0;
        Long l = null;
        j jVar = null;
        String str = null;
        Long l2 = null;
        long j = 0;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    l = (Long) aVarC.v(descriptor2, 0, P.a, l);
                    i |= 1;
                    break;
                case 1:
                    j = aVarC.j(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    jVar = (j) aVarC.z(descriptor2, 2, i.f, jVar);
                    i |= 4;
                    break;
                case 3:
                    str = (String) aVarC.v(descriptor2, 3, q0.a, str);
                    i |= 8;
                    break;
                case 4:
                    l2 = (Long) aVarC.v(descriptor2, 4, P.a, l2);
                    i |= 16;
                    break;
                case 5:
                    list = (List) aVarC.v(descriptor2, 5, kSerializerArr[5], list);
                    i |= 32;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new SrsRequest(i, l, j, jVar, str, l2, list);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull SrsRequest value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        SrsRequest.Companion companion = SrsRequest.Companion;
        if (bVarC.D(descriptor2) || value.a != null) {
            bVarC.s(descriptor2, 0, P.a, value.a);
        }
        bVarC.C(descriptor2, 1, value.b);
        bVarC.i(descriptor2, 2, i.f, value.c);
        boolean zD = bVarC.D(descriptor2);
        String str = value.d;
        if (zD || str != null) {
            bVarC.s(descriptor2, 3, q0.a, str);
        }
        boolean zD2 = bVarC.D(descriptor2);
        Long l = value.e;
        if (zD2 || l != null) {
            bVarC.s(descriptor2, 4, P.a, l);
        }
        boolean zD3 = bVarC.D(descriptor2);
        List list = value.f;
        if (zD3 || list != null) {
            bVarC.s(descriptor2, 5, SrsRequest.g[5], list);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
