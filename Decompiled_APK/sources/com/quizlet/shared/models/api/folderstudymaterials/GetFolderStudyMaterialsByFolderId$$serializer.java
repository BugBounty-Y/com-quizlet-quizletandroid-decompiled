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
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class GetFolderStudyMaterialsByFolderId$$serializer implements D {

    @NotNull
    public static final GetFolderStudyMaterialsByFolderId$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        GetFolderStudyMaterialsByFolderId$$serializer getFolderStudyMaterialsByFolderId$$serializer = new GetFolderStudyMaterialsByFolderId$$serializer();
        INSTANCE = getFolderStudyMaterialsByFolderId$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("GetFolderStudyMaterialsByFolderId", getFolderStudyMaterialsByFolderId$$serializer, 2);
        pluginGeneratedSerialDescriptor.k("folderIds", false);
        pluginGeneratedSerialDescriptor.k("includeModels", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private GetFolderStudyMaterialsByFolderId$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{GetFolderStudyMaterialsByFolderId.d[0], C5053g.a};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public GetFolderStudyMaterialsByFolderId deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = GetFolderStudyMaterialsByFolderId.d;
        List list = null;
        boolean z = true;
        int i = 0;
        boolean zQ = false;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                list = (List) aVarC.z(descriptor2, 0, kSerializerArr[0], list);
                i |= 1;
            } else {
                if (iT != 1) {
                    throw new UnknownFieldException(iT);
                }
                zQ = aVarC.q(descriptor2, 1);
                i |= 2;
            }
        }
        aVarC.b(descriptor2);
        return new GetFolderStudyMaterialsByFolderId(zQ, i, list);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull GetFolderStudyMaterialsByFolderId value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.i(descriptor2, 0, GetFolderStudyMaterialsByFolderId.d[0], value.b);
        boolean zD = bVarC.D(descriptor2);
        boolean z = value.c;
        if (zD || !z) {
            bVarC.p(descriptor2, 1, z);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
