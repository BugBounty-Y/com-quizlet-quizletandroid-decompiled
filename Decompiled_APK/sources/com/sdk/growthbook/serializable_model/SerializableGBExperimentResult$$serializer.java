package com.sdk.growthbook.serializable_model;

import com.google.android.gms.ads.g;
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
import kotlinx.serialization.internal.C;
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.l0;
import kotlinx.serialization.internal.q0;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.m;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public /* synthetic */ class SerializableGBExperimentResult$$serializer implements D {

    @NotNull
    public static final SerializableGBExperimentResult$$serializer INSTANCE;

    @NotNull
    private static final SerialDescriptor descriptor;

    static {
        SerializableGBExperimentResult$$serializer serializableGBExperimentResult$$serializer = new SerializableGBExperimentResult$$serializer();
        INSTANCE = serializableGBExperimentResult$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.sdk.growthbook.serializable_model.SerializableGBExperimentResult", serializableGBExperimentResult$$serializer, 12);
        pluginGeneratedSerialDescriptor.k("inExperiment", true);
        pluginGeneratedSerialDescriptor.k("variationId", true);
        pluginGeneratedSerialDescriptor.k("value", true);
        pluginGeneratedSerialDescriptor.k("hashAttribute", true);
        pluginGeneratedSerialDescriptor.k("hashValue", true);
        pluginGeneratedSerialDescriptor.k("key", true);
        pluginGeneratedSerialDescriptor.k("name", true);
        pluginGeneratedSerialDescriptor.k("bucket", true);
        pluginGeneratedSerialDescriptor.k("passthrough", true);
        pluginGeneratedSerialDescriptor.k("hashUsed", true);
        pluginGeneratedSerialDescriptor.k("featureId", true);
        pluginGeneratedSerialDescriptor.k("stickyBucketUsed", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private SerializableGBExperimentResult$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public final KSerializer[] childSerializers() {
        C5053g c5053g = C5053g.a;
        q0 q0Var = q0.a;
        return new KSerializer[]{c5053g, K.a, m.a, R1.e(q0Var), R1.e(q0Var), q0Var, R1.e(q0Var), R1.e(C.a), R1.e(c5053g), R1.e(c5053g), R1.e(q0Var), R1.e(c5053g)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerializableGBExperimentResult deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor serialDescriptor = descriptor;
        a aVarC = decoder.c(serialDescriptor);
        Boolean bool = null;
        String str = null;
        Boolean bool2 = null;
        k kVar = null;
        String str2 = null;
        String str3 = null;
        String strR = null;
        String str4 = null;
        Float f = null;
        Boolean bool3 = null;
        boolean z = true;
        int i = 0;
        boolean zQ = false;
        int iN = 0;
        while (z) {
            int iT = aVarC.t(serialDescriptor);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    zQ = aVarC.q(serialDescriptor, 0);
                    i |= 1;
                    break;
                case 1:
                    iN = aVarC.n(serialDescriptor, 1);
                    i |= 2;
                    break;
                case 2:
                    kVar = (k) aVarC.z(serialDescriptor, 2, m.a, kVar);
                    i |= 4;
                    break;
                case 3:
                    str2 = (String) aVarC.v(serialDescriptor, 3, q0.a, str2);
                    i |= 8;
                    break;
                case 4:
                    str3 = (String) aVarC.v(serialDescriptor, 4, q0.a, str3);
                    i |= 16;
                    break;
                case 5:
                    strR = aVarC.r(serialDescriptor, 5);
                    i |= 32;
                    break;
                case 6:
                    str4 = (String) aVarC.v(serialDescriptor, 6, q0.a, str4);
                    i |= 64;
                    break;
                case 7:
                    f = (Float) aVarC.v(serialDescriptor, 7, C.a, f);
                    i |= 128;
                    break;
                case 8:
                    bool3 = (Boolean) aVarC.v(serialDescriptor, 8, C5053g.a, bool3);
                    i |= 256;
                    break;
                case 9:
                    bool = (Boolean) aVarC.v(serialDescriptor, 9, C5053g.a, bool);
                    i |= g.MAX_CONTENT_URL_LENGTH;
                    break;
                case 10:
                    str = (String) aVarC.v(serialDescriptor, 10, q0.a, str);
                    i |= 1024;
                    break;
                case 11:
                    bool2 = (Boolean) aVarC.v(serialDescriptor, 11, C5053g.a, bool2);
                    i |= 2048;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(serialDescriptor);
        return new SerializableGBExperimentResult(i, zQ, iN, kVar, str2, str3, strR, str4, f, bool3, bool, str, bool2, (l0) null);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(@NotNull Encoder encoder, @NotNull SerializableGBExperimentResult value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor serialDescriptor = descriptor;
        b bVarC = encoder.c(serialDescriptor);
        SerializableGBExperimentResult.write$Self$GrowthBook_release(value, bVarC, serialDescriptor);
        bVarC.b(serialDescriptor);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
