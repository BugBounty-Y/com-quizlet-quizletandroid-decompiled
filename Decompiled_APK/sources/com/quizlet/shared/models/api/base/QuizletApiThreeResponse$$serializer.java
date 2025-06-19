package com.quizlet.shared.models.api.base;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.shared.models.api.base.QuizletApiThreeResponse;
import com.quizlet.shared.models.api.base.errors.QuizletApiError;
import com.quizlet.shared.models.api.base.errors.QuizletApiError$$serializer;
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
public final class QuizletApiThreeResponse$$serializer implements D {

    @NotNull
    public static final QuizletApiThreeResponse$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        QuizletApiThreeResponse$$serializer quizletApiThreeResponse$$serializer = new QuizletApiThreeResponse$$serializer();
        INSTANCE = quizletApiThreeResponse$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.base.QuizletApiThreeResponse", quizletApiThreeResponse$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("models", true);
        pluginGeneratedSerialDescriptor.k("data", true);
        pluginGeneratedSerialDescriptor.k("error", true);
        pluginGeneratedSerialDescriptor.k("validationErrors", true);
        pluginGeneratedSerialDescriptor.k("paging", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private QuizletApiThreeResponse$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{R1.e(ModelWrapper$$serializer.INSTANCE), R1.e(DataWrapper$$serializer.INSTANCE), R1.e(QuizletApiError$$serializer.INSTANCE), R1.e(QuizletApiThreeResponse.f[3]), R1.e(PagingInfo$$serializer.INSTANCE)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public QuizletApiThreeResponse deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = QuizletApiThreeResponse.f;
        int i = 0;
        ModelWrapper modelWrapper = null;
        DataWrapper dataWrapper = null;
        QuizletApiError quizletApiError = null;
        List list = null;
        PagingInfo pagingInfo = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                modelWrapper = (ModelWrapper) aVarC.v(descriptor2, 0, ModelWrapper$$serializer.INSTANCE, modelWrapper);
                i |= 1;
            } else if (iT == 1) {
                dataWrapper = (DataWrapper) aVarC.v(descriptor2, 1, DataWrapper$$serializer.INSTANCE, dataWrapper);
                i |= 2;
            } else if (iT == 2) {
                quizletApiError = (QuizletApiError) aVarC.v(descriptor2, 2, QuizletApiError$$serializer.INSTANCE, quizletApiError);
                i |= 4;
            } else if (iT == 3) {
                list = (List) aVarC.v(descriptor2, 3, kSerializerArr[3], list);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                pagingInfo = (PagingInfo) aVarC.v(descriptor2, 4, PagingInfo$$serializer.INSTANCE, pagingInfo);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new QuizletApiThreeResponse(i, modelWrapper, dataWrapper, quizletApiError, list, pagingInfo);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull QuizletApiThreeResponse value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        QuizletApiThreeResponse.Companion companion = QuizletApiThreeResponse.Companion;
        if (bVarC.D(descriptor2) || value.a != null) {
            bVarC.s(descriptor2, 0, ModelWrapper$$serializer.INSTANCE, value.a);
        }
        if (bVarC.D(descriptor2) || value.b != null) {
            bVarC.s(descriptor2, 1, DataWrapper$$serializer.INSTANCE, value.b);
        }
        if (bVarC.D(descriptor2) || value.c != null) {
            bVarC.s(descriptor2, 2, QuizletApiError$$serializer.INSTANCE, value.c);
        }
        if (bVarC.D(descriptor2) || value.d != null) {
            bVarC.s(descriptor2, 3, QuizletApiThreeResponse.f[3], value.d);
        }
        if (bVarC.D(descriptor2) || value.e != null) {
            bVarC.s(descriptor2, 4, PagingInfo$$serializer.INSTANCE, value.e);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
