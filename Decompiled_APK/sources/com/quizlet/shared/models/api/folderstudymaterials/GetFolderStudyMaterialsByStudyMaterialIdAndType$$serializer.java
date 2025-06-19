package com.quizlet.shared.models.api.folderstudymaterials;

import com.quizlet.shared.enums.o;
import com.quizlet.shared.enums.p;
import java.util.List;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.collections.K;
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
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class GetFolderStudyMaterialsByStudyMaterialIdAndType$$serializer implements D {

    @NotNull
    public static final GetFolderStudyMaterialsByStudyMaterialIdAndType$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        GetFolderStudyMaterialsByStudyMaterialIdAndType$$serializer getFolderStudyMaterialsByStudyMaterialIdAndType$$serializer = new GetFolderStudyMaterialsByStudyMaterialIdAndType$$serializer();
        INSTANCE = getFolderStudyMaterialsByStudyMaterialIdAndType$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("GetFolderStudyMaterialsByStudyMaterialIdAndType", getFolderStudyMaterialsByStudyMaterialIdAndType$$serializer, 4);
        pluginGeneratedSerialDescriptor.k("studyMaterialId", false);
        pluginGeneratedSerialDescriptor.k("studyMaterialType", false);
        pluginGeneratedSerialDescriptor.k("folderIds", true);
        pluginGeneratedSerialDescriptor.k("includeModels", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private GetFolderStudyMaterialsByStudyMaterialIdAndType$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{q0.a, o.f, GetFolderStudyMaterialsByStudyMaterialIdAndType.f[2], C5053g.a};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public GetFolderStudyMaterialsByStudyMaterialIdAndType deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = GetFolderStudyMaterialsByStudyMaterialIdAndType.f;
        int i = 0;
        boolean zQ = false;
        String strR = null;
        p pVar = null;
        List list = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                strR = aVarC.r(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                pVar = (p) aVarC.z(descriptor2, 1, o.f, pVar);
                i |= 2;
            } else if (iT == 2) {
                list = (List) aVarC.z(descriptor2, 2, kSerializerArr[2], list);
                i |= 4;
            } else {
                if (iT != 3) {
                    throw new UnknownFieldException(iT);
                }
                zQ = aVarC.q(descriptor2, 3);
                i |= 8;
            }
        }
        aVarC.b(descriptor2);
        return new GetFolderStudyMaterialsByStudyMaterialIdAndType(i, strR, pVar, list, zQ);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull GetFolderStudyMaterialsByStudyMaterialIdAndType value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.b);
        bVarC.i(descriptor2, 1, o.f, value.c);
        boolean zD = bVarC.D(descriptor2);
        List list = value.d;
        if (zD || !Intrinsics.b(list, K.a)) {
            bVarC.i(descriptor2, 2, GetFolderStudyMaterialsByStudyMaterialIdAndType.f[2], list);
        }
        boolean zD2 = bVarC.D(descriptor2);
        boolean z = value.e;
        if (zD2 || !z) {
            bVarC.p(descriptor2, 3, z);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
