package com.sdk.growthbook.utils;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.sdk.growthbook.utils.RangeSerializer;
import java.util.List;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.l0;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public /* synthetic */ class GBFilter$$serializer implements D {

    @NotNull
    public static final GBFilter$$serializer INSTANCE;

    @NotNull
    private static final SerialDescriptor descriptor;

    static {
        GBFilter$$serializer gBFilter$$serializer = new GBFilter$$serializer();
        INSTANCE = gBFilter$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.sdk.growthbook.utils.GBFilter", gBFilter$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("seed", false);
        pluginGeneratedSerialDescriptor.k("ranges", false);
        pluginGeneratedSerialDescriptor.k("attribute", true);
        pluginGeneratedSerialDescriptor.k("hashVersion", true);
        pluginGeneratedSerialDescriptor.k("fallbackAttribute", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private GBFilter$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public final KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        return new KSerializer[]{q0Var, RangeSerializer.GBBucketRangeListSerializer.INSTANCE, R1.e(q0Var), R1.e(K.a), R1.e(q0Var)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final GBFilter deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor serialDescriptor = descriptor;
        kotlinx.serialization.encoding.a aVarC = decoder.c(serialDescriptor);
        int i = 0;
        String strR = null;
        List list = null;
        String str = null;
        Integer num = null;
        String str2 = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(serialDescriptor);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                strR = aVarC.r(serialDescriptor, 0);
                i |= 1;
            } else if (iT == 1) {
                list = (List) aVarC.z(serialDescriptor, 1, RangeSerializer.GBBucketRangeListSerializer.INSTANCE, list);
                i |= 2;
            } else if (iT == 2) {
                str = (String) aVarC.v(serialDescriptor, 2, q0.a, str);
                i |= 4;
            } else if (iT == 3) {
                num = (Integer) aVarC.v(serialDescriptor, 3, K.a, num);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                str2 = (String) aVarC.v(serialDescriptor, 4, q0.a, str2);
                i |= 16;
            }
        }
        aVarC.b(serialDescriptor);
        return new GBFilter(i, strR, list, str, num, str2, (l0) null);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(@NotNull Encoder encoder, @NotNull GBFilter value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor serialDescriptor = descriptor;
        b bVarC = encoder.c(serialDescriptor);
        GBFilter.write$Self$GrowthBook_release(value, bVarC, serialDescriptor);
        bVarC.b(serialDescriptor);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
