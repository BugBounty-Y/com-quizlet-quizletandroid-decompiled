package com.sdk.growthbook.utils;

import java.util.Map;
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
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public /* synthetic */ class GBStickyAssignmentsDocument$$serializer implements D {

    @NotNull
    public static final GBStickyAssignmentsDocument$$serializer INSTANCE;

    @NotNull
    private static final SerialDescriptor descriptor;

    static {
        GBStickyAssignmentsDocument$$serializer gBStickyAssignmentsDocument$$serializer = new GBStickyAssignmentsDocument$$serializer();
        INSTANCE = gBStickyAssignmentsDocument$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.sdk.growthbook.utils.GBStickyAssignmentsDocument", gBStickyAssignmentsDocument$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("attributeName", false);
        pluginGeneratedSerialDescriptor.k("attributeValue", false);
        pluginGeneratedSerialDescriptor.k("assignments", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private GBStickyAssignmentsDocument$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public final KSerializer[] childSerializers() {
        KSerializer kSerializer = GBStickyAssignmentsDocument.$childSerializers[2];
        q0 q0Var = q0.a;
        return new KSerializer[]{q0Var, q0Var, kSerializer};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final GBStickyAssignmentsDocument deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor serialDescriptor = descriptor;
        kotlinx.serialization.encoding.a aVarC = decoder.c(serialDescriptor);
        KSerializer[] kSerializerArr = GBStickyAssignmentsDocument.$childSerializers;
        int i = 0;
        String strR = null;
        String strR2 = null;
        Map map = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(serialDescriptor);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                strR = aVarC.r(serialDescriptor, 0);
                i |= 1;
            } else if (iT == 1) {
                strR2 = aVarC.r(serialDescriptor, 1);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                map = (Map) aVarC.z(serialDescriptor, 2, kSerializerArr[2], map);
                i |= 4;
            }
        }
        aVarC.b(serialDescriptor);
        return new GBStickyAssignmentsDocument(i, strR, strR2, map, null);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(@NotNull Encoder encoder, @NotNull GBStickyAssignmentsDocument value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor serialDescriptor = descriptor;
        b bVarC = encoder.c(serialDescriptor);
        GBStickyAssignmentsDocument.write$Self$GrowthBook_release(value, bVarC, serialDescriptor);
        bVarC.b(serialDescriptor);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
