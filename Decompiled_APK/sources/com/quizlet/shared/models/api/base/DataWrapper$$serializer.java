package com.quizlet.shared.models.api.base;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.shared.models.api.base.DataWrapper;
import com.quizlet.shared.models.api.grading.LongtextGradingResult;
import com.quizlet.shared.models.api.grading.LongtextGradingResult$$serializer;
import com.quizlet.shared.models.api.srs.SrsResponse;
import com.quizlet.shared.models.api.srs.SrsResponse$$serializer;
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
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class DataWrapper$$serializer implements D {

    @NotNull
    public static final DataWrapper$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        DataWrapper$$serializer dataWrapper$$serializer = new DataWrapper$$serializer();
        INSTANCE = dataWrapper$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.base.DataWrapper", dataWrapper$$serializer, 7);
        pluginGeneratedSerialDescriptor.k("longtextGradingResult", true);
        pluginGeneratedSerialDescriptor.k("srsResponse", true);
        pluginGeneratedSerialDescriptor.k("newStudyNotes", true);
        pluginGeneratedSerialDescriptor.k("studyNotesArtifacts", true);
        pluginGeneratedSerialDescriptor.k("studyNotes", true);
        pluginGeneratedSerialDescriptor.k("features", true);
        pluginGeneratedSerialDescriptor.k("studiableMetadataStatus", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private DataWrapper$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = DataWrapper.h;
        return new KSerializer[]{R1.e(LongtextGradingResult$$serializer.INSTANCE), R1.e(SrsResponse$$serializer.INSTANCE), R1.e(kSerializerArr[2]), R1.e(kSerializerArr[3]), R1.e(kSerializerArr[4]), R1.e(kSerializerArr[5]), R1.e(kSerializerArr[6])};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public DataWrapper deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = DataWrapper.h;
        int i = 0;
        LongtextGradingResult longtextGradingResult = null;
        SrsResponse srsResponse = null;
        List list = null;
        List list2 = null;
        List list3 = null;
        List list4 = null;
        List list5 = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    longtextGradingResult = (LongtextGradingResult) aVarC.v(descriptor2, 0, LongtextGradingResult$$serializer.INSTANCE, longtextGradingResult);
                    i |= 1;
                    break;
                case 1:
                    srsResponse = (SrsResponse) aVarC.v(descriptor2, 1, SrsResponse$$serializer.INSTANCE, srsResponse);
                    i |= 2;
                    break;
                case 2:
                    list = (List) aVarC.v(descriptor2, 2, kSerializerArr[2], list);
                    i |= 4;
                    break;
                case 3:
                    list2 = (List) aVarC.v(descriptor2, 3, kSerializerArr[3], list2);
                    i |= 8;
                    break;
                case 4:
                    list3 = (List) aVarC.v(descriptor2, 4, kSerializerArr[4], list3);
                    i |= 16;
                    break;
                case 5:
                    list4 = (List) aVarC.v(descriptor2, 5, kSerializerArr[5], list4);
                    i |= 32;
                    break;
                case 6:
                    list5 = (List) aVarC.v(descriptor2, 6, kSerializerArr[6], list5);
                    i |= 64;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new DataWrapper(i, longtextGradingResult, srsResponse, list, list2, list3, list4, list5);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull DataWrapper value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        DataWrapper.Companion companion = DataWrapper.Companion;
        if (bVarC.D(descriptor2) || value.a != null) {
            bVarC.s(descriptor2, 0, LongtextGradingResult$$serializer.INSTANCE, value.a);
        }
        if (bVarC.D(descriptor2) || value.b != null) {
            bVarC.s(descriptor2, 1, SrsResponse$$serializer.INSTANCE, value.b);
        }
        boolean zD = bVarC.D(descriptor2);
        KSerializer[] kSerializerArr = DataWrapper.h;
        if (zD || value.c != null) {
            bVarC.s(descriptor2, 2, kSerializerArr[2], value.c);
        }
        if (bVarC.D(descriptor2) || value.d != null) {
            bVarC.s(descriptor2, 3, kSerializerArr[3], value.d);
        }
        if (bVarC.D(descriptor2) || value.e != null) {
            bVarC.s(descriptor2, 4, kSerializerArr[4], value.e);
        }
        if (bVarC.D(descriptor2) || value.f != null) {
            bVarC.s(descriptor2, 5, kSerializerArr[5], value.f);
        }
        if (bVarC.D(descriptor2) || value.g != null) {
            bVarC.s(descriptor2, 6, kSerializerArr[6], value.g);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
