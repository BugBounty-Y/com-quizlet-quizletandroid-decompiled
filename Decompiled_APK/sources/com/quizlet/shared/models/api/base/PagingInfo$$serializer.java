package com.quizlet.shared.models.api.base;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
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
public final class PagingInfo$$serializer implements D {

    @NotNull
    public static final PagingInfo$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        PagingInfo$$serializer pagingInfo$$serializer = new PagingInfo$$serializer();
        INSTANCE = pagingInfo$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.base.PagingInfo", pagingInfo$$serializer, 4);
        pluginGeneratedSerialDescriptor.k("total", false);
        pluginGeneratedSerialDescriptor.k("page", false);
        pluginGeneratedSerialDescriptor.k("perPage", false);
        pluginGeneratedSerialDescriptor.k("token", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private PagingInfo$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer kSerializerE = R1.e(q0.a);
        K k = K.a;
        return new KSerializer[]{k, k, k, kSerializerE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public PagingInfo deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        int i = 0;
        int iN = 0;
        int iN2 = 0;
        int iN3 = 0;
        String str = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                iN = aVarC.n(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                iN2 = aVarC.n(descriptor2, 1);
                i |= 2;
            } else if (iT == 2) {
                iN3 = aVarC.n(descriptor2, 2);
                i |= 4;
            } else {
                if (iT != 3) {
                    throw new UnknownFieldException(iT);
                }
                str = (String) aVarC.v(descriptor2, 3, q0.a, str);
                i |= 8;
            }
        }
        aVarC.b(descriptor2);
        return new PagingInfo(i, iN, iN2, iN3, str);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull PagingInfo value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.l(0, value.a, descriptor2);
        bVarC.l(1, value.b, descriptor2);
        bVarC.l(2, value.c, descriptor2);
        boolean zD = bVarC.D(descriptor2);
        String str = value.d;
        if (zD || str != null) {
            bVarC.s(descriptor2, 3, q0.a, str);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
