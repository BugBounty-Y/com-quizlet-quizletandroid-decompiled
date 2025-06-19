package com.sdk.growthbook.utils;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
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
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.l0;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public /* synthetic */ class GBVariationMeta$$serializer implements D {

    @NotNull
    public static final GBVariationMeta$$serializer INSTANCE;

    @NotNull
    private static final SerialDescriptor descriptor;

    static {
        GBVariationMeta$$serializer gBVariationMeta$$serializer = new GBVariationMeta$$serializer();
        INSTANCE = gBVariationMeta$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.sdk.growthbook.utils.GBVariationMeta", gBVariationMeta$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("key", true);
        pluginGeneratedSerialDescriptor.k("name", true);
        pluginGeneratedSerialDescriptor.k("passthrough", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private GBVariationMeta$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public final KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        return new KSerializer[]{R1.e(q0Var), R1.e(q0Var), R1.e(C5053g.a)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final GBVariationMeta deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor serialDescriptor = descriptor;
        kotlinx.serialization.encoding.a aVarC = decoder.c(serialDescriptor);
        int i = 0;
        String str = null;
        String str2 = null;
        Boolean bool = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(serialDescriptor);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                str = (String) aVarC.v(serialDescriptor, 0, q0.a, str);
                i |= 1;
            } else if (iT == 1) {
                str2 = (String) aVarC.v(serialDescriptor, 1, q0.a, str2);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                bool = (Boolean) aVarC.v(serialDescriptor, 2, C5053g.a, bool);
                i |= 4;
            }
        }
        aVarC.b(serialDescriptor);
        return new GBVariationMeta(i, str, str2, bool, (l0) null);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(@NotNull Encoder encoder, @NotNull GBVariationMeta value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor serialDescriptor = descriptor;
        b bVarC = encoder.c(serialDescriptor);
        GBVariationMeta.write$Self$GrowthBook_release(value, bVarC, serialDescriptor);
        bVarC.b(serialDescriptor);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
