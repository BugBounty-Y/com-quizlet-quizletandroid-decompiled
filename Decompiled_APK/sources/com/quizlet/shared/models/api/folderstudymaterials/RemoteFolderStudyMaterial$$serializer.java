package com.quizlet.shared.models.api.folderstudymaterials;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class RemoteFolderStudyMaterial$$serializer implements D {

    @NotNull
    public static final RemoteFolderStudyMaterial$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RemoteFolderStudyMaterial$$serializer remoteFolderStudyMaterial$$serializer = new RemoteFolderStudyMaterial$$serializer();
        INSTANCE = remoteFolderStudyMaterial$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.folderstudymaterials.RemoteFolderStudyMaterial", remoteFolderStudyMaterial$$serializer, 9);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("folderId", false);
        pluginGeneratedSerialDescriptor.k("studyMaterialId", false);
        pluginGeneratedSerialDescriptor.k("studyMaterialType", false);
        pluginGeneratedSerialDescriptor.k("userId", false);
        pluginGeneratedSerialDescriptor.k("subFolderId", false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        pluginGeneratedSerialDescriptor.k("lastModified", false);
        pluginGeneratedSerialDescriptor.k("isDeleted", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RemoteFolderStudyMaterial$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        P p = P.a;
        return new KSerializer[]{R1.e(p), R1.e(p), R1.e(q0.a), R1.e(K.a), R1.e(p), R1.e(p), R1.e(p), R1.e(p), R1.e(C5053g.a)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RemoteFolderStudyMaterial deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        Long l = null;
        Long l2 = null;
        String str = null;
        Integer num = null;
        Long l3 = null;
        Long l4 = null;
        Long l5 = null;
        Long l6 = null;
        Boolean bool = null;
        int i = 0;
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
                    l2 = (Long) aVarC.v(descriptor2, 1, P.a, l2);
                    i |= 2;
                    break;
                case 2:
                    str = (String) aVarC.v(descriptor2, 2, q0.a, str);
                    i |= 4;
                    break;
                case 3:
                    num = (Integer) aVarC.v(descriptor2, 3, K.a, num);
                    i |= 8;
                    break;
                case 4:
                    l3 = (Long) aVarC.v(descriptor2, 4, P.a, l3);
                    i |= 16;
                    break;
                case 5:
                    l4 = (Long) aVarC.v(descriptor2, 5, P.a, l4);
                    i |= 32;
                    break;
                case 6:
                    l5 = (Long) aVarC.v(descriptor2, 6, P.a, l5);
                    i |= 64;
                    break;
                case 7:
                    l6 = (Long) aVarC.v(descriptor2, 7, P.a, l6);
                    i |= 128;
                    break;
                case 8:
                    bool = (Boolean) aVarC.v(descriptor2, 8, C5053g.a, bool);
                    i |= 256;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new RemoteFolderStudyMaterial(i, l, l2, str, num, l3, l4, l5, l6, bool);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RemoteFolderStudyMaterial value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        P p = P.a;
        bVarC.s(descriptor2, 0, p, value.a);
        bVarC.s(descriptor2, 1, p, value.b);
        bVarC.s(descriptor2, 2, q0.a, value.c);
        bVarC.s(descriptor2, 3, K.a, value.d);
        bVarC.s(descriptor2, 4, p, value.e);
        bVarC.s(descriptor2, 5, p, value.f);
        bVarC.s(descriptor2, 6, p, value.g);
        bVarC.s(descriptor2, 7, p, value.h);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.i;
        if (zD || bool != null) {
            bVarC.s(descriptor2, 8, C5053g.a, bool);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
