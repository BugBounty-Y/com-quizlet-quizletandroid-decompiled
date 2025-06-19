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
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.m;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public /* synthetic */ class GBParentConditionInterface$$serializer implements D {

    @NotNull
    public static final GBParentConditionInterface$$serializer INSTANCE;

    @NotNull
    private static final SerialDescriptor descriptor;

    static {
        GBParentConditionInterface$$serializer gBParentConditionInterface$$serializer = new GBParentConditionInterface$$serializer();
        INSTANCE = gBParentConditionInterface$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.sdk.growthbook.utils.GBParentConditionInterface", gBParentConditionInterface$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("condition", false);
        pluginGeneratedSerialDescriptor.k("gate", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private GBParentConditionInterface$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public final KSerializer[] childSerializers() {
        return new KSerializer[]{q0.a, m.a, R1.e(C5053g.a)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final GBParentConditionInterface deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor serialDescriptor = descriptor;
        kotlinx.serialization.encoding.a aVarC = decoder.c(serialDescriptor);
        int i = 0;
        String strR = null;
        k kVar = null;
        Boolean bool = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(serialDescriptor);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                strR = aVarC.r(serialDescriptor, 0);
                i |= 1;
            } else if (iT == 1) {
                kVar = (k) aVarC.z(serialDescriptor, 1, m.a, kVar);
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
        return new GBParentConditionInterface(i, strR, kVar, bool, (l0) null);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(@NotNull Encoder encoder, @NotNull GBParentConditionInterface value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor serialDescriptor = descriptor;
        b bVarC = encoder.c(serialDescriptor);
        GBParentConditionInterface.write$Self$GrowthBook_release(value, bVarC, serialDescriptor);
        bVarC.b(serialDescriptor);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
