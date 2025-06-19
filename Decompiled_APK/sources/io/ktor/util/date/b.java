package io.ktor.util.date;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements D {
    public static final b a;

    @NotNull
    private static final SerialDescriptor descriptor;

    static {
        b bVar = new b();
        a = bVar;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("io.ktor.util.date.GMTDate", bVar, 9);
        pluginGeneratedSerialDescriptor.k("seconds", false);
        pluginGeneratedSerialDescriptor.k("minutes", false);
        pluginGeneratedSerialDescriptor.k("hours", false);
        pluginGeneratedSerialDescriptor.k("dayOfWeek", false);
        pluginGeneratedSerialDescriptor.k("dayOfMonth", false);
        pluginGeneratedSerialDescriptor.k("dayOfYear", false);
        pluginGeneratedSerialDescriptor.k("month", false);
        pluginGeneratedSerialDescriptor.k("year", false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    @Override // kotlinx.serialization.internal.D
    public final KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = d.j;
        KSerializer kSerializer = kSerializerArr[3];
        KSerializer kSerializer2 = kSerializerArr[6];
        K k = K.a;
        return new KSerializer[]{k, k, k, kSerializer, k, k, kSerializer2, k, P.a};
    }

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor serialDescriptor = descriptor;
        kotlinx.serialization.encoding.a aVarC = decoder.c(serialDescriptor);
        KSerializer[] kSerializerArr = d.j;
        e eVar = null;
        int i = 0;
        int iN = 0;
        int iN2 = 0;
        int iN3 = 0;
        int iN4 = 0;
        int iN5 = 0;
        int iN6 = 0;
        f fVar = null;
        long j = 0;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(serialDescriptor);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    iN = aVarC.n(serialDescriptor, 0);
                    i |= 1;
                    break;
                case 1:
                    iN2 = aVarC.n(serialDescriptor, 1);
                    i |= 2;
                    break;
                case 2:
                    iN3 = aVarC.n(serialDescriptor, 2);
                    i |= 4;
                    break;
                case 3:
                    fVar = (f) aVarC.z(serialDescriptor, 3, kSerializerArr[3], fVar);
                    i |= 8;
                    break;
                case 4:
                    iN4 = aVarC.n(serialDescriptor, 4);
                    i |= 16;
                    break;
                case 5:
                    iN5 = aVarC.n(serialDescriptor, 5);
                    i |= 32;
                    break;
                case 6:
                    eVar = (e) aVarC.z(serialDescriptor, 6, kSerializerArr[6], eVar);
                    i |= 64;
                    break;
                case 7:
                    iN6 = aVarC.n(serialDescriptor, 7);
                    i |= 128;
                    break;
                case 8:
                    j = aVarC.j(serialDescriptor, 8);
                    i |= 256;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(serialDescriptor);
        return new d(i, iN, iN2, iN3, fVar, iN4, iN5, eVar, iN6, j);
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        d value = (d) obj;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor serialDescriptor = descriptor;
        kotlinx.serialization.encoding.b bVarC = encoder.c(serialDescriptor);
        bVarC.l(0, value.a, serialDescriptor);
        bVarC.l(1, value.b, serialDescriptor);
        bVarC.l(2, value.c, serialDescriptor);
        KSerializer[] kSerializerArr = d.j;
        bVarC.i(serialDescriptor, 3, kSerializerArr[3], value.d);
        bVarC.l(4, value.e, serialDescriptor);
        bVarC.l(5, value.f, serialDescriptor);
        bVarC.i(serialDescriptor, 6, kSerializerArr[6], value.g);
        bVarC.l(7, value.h, serialDescriptor);
        bVarC.C(serialDescriptor, 8, value.i);
        bVarC.b(serialDescriptor);
    }

    @Override // kotlinx.serialization.internal.D
    public final KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
