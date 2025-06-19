package com.quizlet.shared.models.api.folderstudymaterials;

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
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class CreateFolderStudyMaterialsRequest$$serializer implements D {

    @NotNull
    public static final CreateFolderStudyMaterialsRequest$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        CreateFolderStudyMaterialsRequest$$serializer createFolderStudyMaterialsRequest$$serializer = new CreateFolderStudyMaterialsRequest$$serializer();
        INSTANCE = createFolderStudyMaterialsRequest$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("CreateFolderStudyMaterialsRequest", createFolderStudyMaterialsRequest$$serializer, 1);
        pluginGeneratedSerialDescriptor.k("data", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private CreateFolderStudyMaterialsRequest$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{CreateFolderStudyMaterialsRequest.c[0]};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public CreateFolderStudyMaterialsRequest deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = CreateFolderStudyMaterialsRequest.c;
        List list = null;
        boolean z = true;
        int i = 0;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else {
                if (iT != 0) {
                    throw new UnknownFieldException(iT);
                }
                list = (List) aVarC.z(descriptor2, 0, kSerializerArr[0], list);
                i = 1;
            }
        }
        aVarC.b(descriptor2);
        return new CreateFolderStudyMaterialsRequest(i, list);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull CreateFolderStudyMaterialsRequest value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.i(descriptor2, 0, CreateFolderStudyMaterialsRequest.c[0], value.b);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
