package com.sdk.growthbook.serializable_model;

import com.google.android.gms.ads.g;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.sdk.growthbook.utils.RangeSerializer;
import java.util.ArrayList;
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
import kotlinx.serialization.internal.C;
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.l0;
import kotlinx.serialization.internal.q0;
import kotlinx.serialization.json.d;
import kotlinx.serialization.json.f;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.m;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public /* synthetic */ class SerializableGBExperiment$$serializer implements D {

    @NotNull
    public static final SerializableGBExperiment$$serializer INSTANCE;

    @NotNull
    private static final SerialDescriptor descriptor;

    static {
        SerializableGBExperiment$$serializer serializableGBExperiment$$serializer = new SerializableGBExperiment$$serializer();
        INSTANCE = serializableGBExperiment$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.sdk.growthbook.serializable_model.SerializableGBExperiment", serializableGBExperiment$$serializer, 21);
        pluginGeneratedSerialDescriptor.k("key", false);
        pluginGeneratedSerialDescriptor.k("variations", true);
        pluginGeneratedSerialDescriptor.k("namespace", true);
        pluginGeneratedSerialDescriptor.k("hashAttribute", true);
        pluginGeneratedSerialDescriptor.k("weights", true);
        pluginGeneratedSerialDescriptor.k("active", true);
        pluginGeneratedSerialDescriptor.k("coverage", true);
        pluginGeneratedSerialDescriptor.k("condition", true);
        pluginGeneratedSerialDescriptor.k("parentConditions", true);
        pluginGeneratedSerialDescriptor.k("force", true);
        pluginGeneratedSerialDescriptor.k("hashVersion", true);
        pluginGeneratedSerialDescriptor.k("ranges", true);
        pluginGeneratedSerialDescriptor.k("meta", true);
        pluginGeneratedSerialDescriptor.k("filters", true);
        pluginGeneratedSerialDescriptor.k("seed", true);
        pluginGeneratedSerialDescriptor.k("name", true);
        pluginGeneratedSerialDescriptor.k("phase", true);
        pluginGeneratedSerialDescriptor.k("fallBackAttribute", true);
        pluginGeneratedSerialDescriptor.k("disableStickyBucketing", true);
        pluginGeneratedSerialDescriptor.k("bucketVersion", true);
        pluginGeneratedSerialDescriptor.k("minBucketVersion", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private SerializableGBExperiment$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public final KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = SerializableGBExperiment.$childSerializers;
        q0 q0Var = q0.a;
        KSerializer kSerializer = kSerializerArr[1];
        KSerializer kSerializerE = R1.e(f.a);
        KSerializer kSerializerE2 = R1.e(q0Var);
        KSerializer kSerializerE3 = R1.e(kSerializerArr[4]);
        C5053g c5053g = C5053g.a;
        KSerializer kSerializerE4 = R1.e(c5053g);
        KSerializer kSerializerE5 = R1.e(C.a);
        KSerializer kSerializerE6 = R1.e(m.a);
        KSerializer kSerializerE7 = R1.e(kSerializerArr[8]);
        K k = K.a;
        return new KSerializer[]{q0Var, kSerializer, kSerializerE, kSerializerE2, kSerializerE3, kSerializerE4, kSerializerE5, kSerializerE6, kSerializerE7, R1.e(k), R1.e(k), R1.e(RangeSerializer.GBBucketRangeListSerializer.INSTANCE), R1.e(kSerializerArr[12]), R1.e(kSerializerArr[13]), R1.e(q0Var), R1.e(q0Var), R1.e(q0Var), R1.e(q0Var), R1.e(c5053g), R1.e(k), R1.e(k)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerializableGBExperiment deserialize(@NotNull Decoder decoder) {
        ArrayList arrayList;
        Integer num;
        int i;
        ArrayList arrayList2;
        Integer num2;
        Boolean bool;
        String str;
        int i2;
        ArrayList arrayList3;
        Integer num3;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor serialDescriptor = descriptor;
        a aVarC = decoder.c(serialDescriptor);
        KSerializer[] kSerializerArr = SerializableGBExperiment.$childSerializers;
        ArrayList arrayList4 = null;
        ArrayList arrayList5 = null;
        ArrayList arrayList6 = null;
        List list = null;
        Integer num4 = null;
        Integer num5 = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        String str5 = null;
        Boolean bool2 = null;
        Integer num6 = null;
        Integer num7 = null;
        String strR = null;
        List list2 = null;
        d dVar = null;
        String str6 = null;
        List list3 = null;
        Boolean bool3 = null;
        Float f = null;
        k kVar = null;
        int i3 = 0;
        int i4 = 1;
        boolean z = true;
        while (z) {
            ArrayList arrayList7 = arrayList4;
            int iT = aVarC.t(serialDescriptor);
            switch (iT) {
                case -1:
                    arrayList = arrayList5;
                    num = num4;
                    i = i4;
                    arrayList2 = arrayList7;
                    num2 = num6;
                    bool = bool3;
                    str = str3;
                    z = false;
                    arrayList4 = arrayList2;
                    str3 = str;
                    arrayList5 = arrayList;
                    i4 = i;
                    bool3 = bool;
                    num6 = num2;
                    num4 = num;
                case 0:
                    arrayList = arrayList5;
                    num = num4;
                    i = i4;
                    arrayList2 = arrayList7;
                    num2 = num6;
                    bool = bool3;
                    str = str3;
                    strR = aVarC.r(serialDescriptor, 0);
                    i3 |= 1;
                    arrayList4 = arrayList2;
                    str3 = str;
                    arrayList5 = arrayList;
                    i4 = i;
                    bool3 = bool;
                    num6 = num2;
                    num4 = num;
                case 1:
                    arrayList = arrayList5;
                    num = num4;
                    KSerializer kSerializer = kSerializerArr[i4];
                    i = i4;
                    arrayList2 = arrayList7;
                    num2 = num6;
                    bool = bool3;
                    str = str3;
                    list2 = (List) aVarC.z(serialDescriptor, i, kSerializer, list2);
                    i3 |= 2;
                    arrayList4 = arrayList2;
                    str3 = str;
                    arrayList5 = arrayList;
                    i4 = i;
                    bool3 = bool;
                    num6 = num2;
                    num4 = num;
                case 2:
                    arrayList3 = arrayList5;
                    num3 = num4;
                    dVar = (d) aVarC.v(serialDescriptor, 2, f.a, dVar);
                    i3 |= 4;
                    arrayList4 = arrayList7;
                    num4 = num3;
                    arrayList5 = arrayList3;
                case 3:
                    arrayList3 = arrayList5;
                    num3 = num4;
                    str6 = (String) aVarC.v(serialDescriptor, 3, q0.a, str6);
                    i3 |= 8;
                    arrayList4 = arrayList7;
                    num4 = num3;
                    arrayList5 = arrayList3;
                case 4:
                    arrayList3 = arrayList5;
                    num3 = num4;
                    list3 = (List) aVarC.v(serialDescriptor, 4, kSerializerArr[4], list3);
                    i3 |= 16;
                    arrayList4 = arrayList7;
                    num4 = num3;
                    arrayList5 = arrayList3;
                case 5:
                    arrayList3 = arrayList5;
                    num3 = num4;
                    bool3 = (Boolean) aVarC.v(serialDescriptor, 5, C5053g.a, bool3);
                    i3 |= 32;
                    arrayList4 = arrayList7;
                    num4 = num3;
                    arrayList5 = arrayList3;
                case 6:
                    arrayList3 = arrayList5;
                    num3 = num4;
                    f = (Float) aVarC.v(serialDescriptor, 6, C.a, f);
                    i3 |= 64;
                    arrayList4 = arrayList7;
                    num4 = num3;
                    arrayList5 = arrayList3;
                case 7:
                    arrayList3 = arrayList5;
                    num3 = num4;
                    kVar = (k) aVarC.v(serialDescriptor, 7, m.a, kVar);
                    i3 |= 128;
                    arrayList4 = arrayList7;
                    num4 = num3;
                    arrayList5 = arrayList3;
                case 8:
                    arrayList3 = arrayList5;
                    num3 = num4;
                    arrayList4 = (ArrayList) aVarC.v(serialDescriptor, 8, kSerializerArr[8], arrayList7);
                    i3 |= 256;
                    num4 = num3;
                    arrayList5 = arrayList3;
                case 9:
                    arrayList3 = arrayList5;
                    num4 = (Integer) aVarC.v(serialDescriptor, 9, K.a, num4);
                    i3 |= g.MAX_CONTENT_URL_LENGTH;
                    arrayList4 = arrayList7;
                    arrayList5 = arrayList3;
                case 10:
                    num = num4;
                    num5 = (Integer) aVarC.v(serialDescriptor, 10, K.a, num5);
                    i3 |= 1024;
                    arrayList4 = arrayList7;
                    num4 = num;
                case 11:
                    num = num4;
                    list = (List) aVarC.v(serialDescriptor, 11, RangeSerializer.GBBucketRangeListSerializer.INSTANCE, list);
                    i3 |= 2048;
                    arrayList4 = arrayList7;
                    num4 = num;
                case 12:
                    num = num4;
                    arrayList6 = (ArrayList) aVarC.v(serialDescriptor, 12, kSerializerArr[12], arrayList6);
                    i3 |= 4096;
                    arrayList4 = arrayList7;
                    num4 = num;
                case 13:
                    num = num4;
                    arrayList5 = (ArrayList) aVarC.v(serialDescriptor, 13, kSerializerArr[13], arrayList5);
                    i3 |= 8192;
                    arrayList4 = arrayList7;
                    num4 = num;
                case 14:
                    num = num4;
                    str2 = (String) aVarC.v(serialDescriptor, 14, q0.a, str2);
                    i3 |= 16384;
                    arrayList4 = arrayList7;
                    num4 = num;
                case 15:
                    num = num4;
                    str3 = (String) aVarC.v(serialDescriptor, 15, q0.a, str3);
                    i2 = 32768;
                    i3 |= i2;
                    arrayList4 = arrayList7;
                    num4 = num;
                case 16:
                    num = num4;
                    str4 = (String) aVarC.v(serialDescriptor, 16, q0.a, str4);
                    i2 = 65536;
                    i3 |= i2;
                    arrayList4 = arrayList7;
                    num4 = num;
                case 17:
                    num = num4;
                    str5 = (String) aVarC.v(serialDescriptor, 17, q0.a, str5);
                    i2 = 131072;
                    i3 |= i2;
                    arrayList4 = arrayList7;
                    num4 = num;
                case 18:
                    num = num4;
                    bool2 = (Boolean) aVarC.v(serialDescriptor, 18, C5053g.a, bool2);
                    i2 = 262144;
                    i3 |= i2;
                    arrayList4 = arrayList7;
                    num4 = num;
                case 19:
                    num = num4;
                    num6 = (Integer) aVarC.v(serialDescriptor, 19, K.a, num6);
                    i2 = 524288;
                    i3 |= i2;
                    arrayList4 = arrayList7;
                    num4 = num;
                case 20:
                    num = num4;
                    num7 = (Integer) aVarC.v(serialDescriptor, 20, K.a, num7);
                    i2 = 1048576;
                    i3 |= i2;
                    arrayList4 = arrayList7;
                    num4 = num;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        ArrayList arrayList8 = arrayList5;
        Integer num8 = num6;
        d dVar2 = dVar;
        Boolean bool4 = bool3;
        String str7 = str3;
        List list4 = list2;
        aVarC.b(serialDescriptor);
        String str8 = strR;
        Integer num9 = num5;
        return new SerializableGBExperiment(i3, str8, list4, dVar2, str6, list3, bool4, f, kVar, arrayList4, num4, num9, list, arrayList6, arrayList8, str2, str7, str4, str5, bool2, num8, num7, (l0) null);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(@NotNull Encoder encoder, @NotNull SerializableGBExperiment value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor serialDescriptor = descriptor;
        b bVarC = encoder.c(serialDescriptor);
        SerializableGBExperiment.write$Self$GrowthBook_release(value, bVarC, serialDescriptor);
        bVarC.b(serialDescriptor);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
