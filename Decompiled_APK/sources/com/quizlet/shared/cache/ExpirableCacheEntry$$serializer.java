package com.quizlet.shared.cache;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
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
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class ExpirableCacheEntry$$serializer implements D {

    @NotNull
    public static final ExpirableCacheEntry$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        ExpirableCacheEntry$$serializer expirableCacheEntry$$serializer = new ExpirableCacheEntry$$serializer();
        INSTANCE = expirableCacheEntry$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("ExpirableCacheEntry", expirableCacheEntry$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("entry", false);
        pluginGeneratedSerialDescriptor.k("expiresAt", false);
        pluginGeneratedSerialDescriptor.k("isStale", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private ExpirableCacheEntry$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{ExpirableCacheEntry.e[0], P.a, R1.e(C5053g.a)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public ExpirableCacheEntry deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = ExpirableCacheEntry.e;
        int i = 0;
        serialization.e eVar = null;
        Boolean bool = null;
        long j = 0;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                eVar = (serialization.e) aVarC.z(descriptor2, 0, kSerializerArr[0], eVar);
                i |= 1;
            } else if (iT == 1) {
                j = aVarC.j(descriptor2, 1);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                bool = (Boolean) aVarC.v(descriptor2, 2, C5053g.a, bool);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new ExpirableCacheEntry(i, eVar, j, bool);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull ExpirableCacheEntry value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.i(descriptor2, 0, ExpirableCacheEntry.e[0], value.b);
        bVarC.C(descriptor2, 1, value.c);
        bVarC.s(descriptor2, 2, C5053g.a, value.d);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
