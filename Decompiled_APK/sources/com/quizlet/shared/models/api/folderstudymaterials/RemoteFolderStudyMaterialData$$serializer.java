package com.quizlet.shared.models.api.folderstudymaterials;

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
/* loaded from: classes3.dex */
public final class RemoteFolderStudyMaterialData$$serializer implements D {

    @NotNull
    public static final RemoteFolderStudyMaterialData$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RemoteFolderStudyMaterialData$$serializer remoteFolderStudyMaterialData$$serializer = new RemoteFolderStudyMaterialData$$serializer();
        INSTANCE = remoteFolderStudyMaterialData$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.folderstudymaterials.RemoteFolderStudyMaterialData", remoteFolderStudyMaterialData$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("folderId", false);
        pluginGeneratedSerialDescriptor.k("studyMaterialId", false);
        pluginGeneratedSerialDescriptor.k("studyMaterialType", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RemoteFolderStudyMaterialData$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{P.a, q0.a, K.a};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RemoteFolderStudyMaterialData deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        int iN = 0;
        long j = 0;
        String strR = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                j = aVarC.j(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                strR = aVarC.r(descriptor2, 1);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                iN = aVarC.n(descriptor2, 2);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new RemoteFolderStudyMaterialData(j, i, iN, strR);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RemoteFolderStudyMaterialData value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.a);
        bVarC.r(descriptor2, 1, value.b);
        bVarC.l(2, value.c, descriptor2);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
