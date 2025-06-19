package com.sdk.growthbook.serializable_model;

import com.comscore.streaming.EventType;
import com.google.android.gms.ads.g;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.sdk.growthbook.utils.OptionalProperty;
import com.sdk.growthbook.utils.RangeSerializer;
import java.util.ArrayList;
import java.util.List;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.Pair;
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
public /* synthetic */ class SerializableGBFeatureRule$$serializer implements D {

    @NotNull
    public static final SerializableGBFeatureRule$$serializer INSTANCE;

    @NotNull
    private static final SerialDescriptor descriptor;

    static {
        SerializableGBFeatureRule$$serializer serializableGBFeatureRule$$serializer = new SerializableGBFeatureRule$$serializer();
        INSTANCE = serializableGBFeatureRule$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.sdk.growthbook.serializable_model.SerializableGBFeatureRule", serializableGBFeatureRule$$serializer, 23);
        pluginGeneratedSerialDescriptor.k("id", true);
        pluginGeneratedSerialDescriptor.k("condition", true);
        pluginGeneratedSerialDescriptor.k("parentConditions", true);
        pluginGeneratedSerialDescriptor.k("coverage", true);
        pluginGeneratedSerialDescriptor.k("force", true);
        pluginGeneratedSerialDescriptor.k("variations", true);
        pluginGeneratedSerialDescriptor.k("key", true);
        pluginGeneratedSerialDescriptor.k("weights", true);
        pluginGeneratedSerialDescriptor.k("namespace", true);
        pluginGeneratedSerialDescriptor.k("hashAttribute", true);
        pluginGeneratedSerialDescriptor.k("hashVersion", true);
        pluginGeneratedSerialDescriptor.k("range", true);
        pluginGeneratedSerialDescriptor.k("ranges", true);
        pluginGeneratedSerialDescriptor.k("meta", true);
        pluginGeneratedSerialDescriptor.k("filters", true);
        pluginGeneratedSerialDescriptor.k("seed", true);
        pluginGeneratedSerialDescriptor.k("name", true);
        pluginGeneratedSerialDescriptor.k("phase", true);
        pluginGeneratedSerialDescriptor.k("fallbackAttribute", true);
        pluginGeneratedSerialDescriptor.k("disableStickyBucketing", true);
        pluginGeneratedSerialDescriptor.k("bucketVersion", true);
        pluginGeneratedSerialDescriptor.k("minBucketVersion", true);
        pluginGeneratedSerialDescriptor.k("tracks", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private SerializableGBFeatureRule$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public final KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = SerializableGBFeatureRule.$childSerializers;
        q0 q0Var = q0.a;
        KSerializer kSerializerE = R1.e(q0Var);
        KSerializer kSerializerE2 = R1.e(m.a);
        KSerializer kSerializerE3 = R1.e(kSerializerArr[2]);
        KSerializer kSerializerE4 = R1.e(C.a);
        KSerializer kSerializer = kSerializerArr[4];
        KSerializer kSerializerE5 = R1.e(kSerializerArr[5]);
        KSerializer kSerializerE6 = R1.e(q0Var);
        KSerializer kSerializerE7 = R1.e(kSerializerArr[7]);
        KSerializer kSerializerE8 = R1.e(f.a);
        KSerializer kSerializerE9 = R1.e(q0Var);
        K k = K.a;
        return new KSerializer[]{kSerializerE, kSerializerE2, kSerializerE3, kSerializerE4, kSerializer, kSerializerE5, kSerializerE6, kSerializerE7, kSerializerE8, kSerializerE9, R1.e(k), R1.e(RangeSerializer.GBBucketRangeSerializer.INSTANCE), R1.e(RangeSerializer.GBBucketRangeListSerializer.INSTANCE), R1.e(kSerializerArr[13]), R1.e(kSerializerArr[14]), R1.e(q0Var), R1.e(q0Var), R1.e(q0Var), R1.e(q0Var), R1.e(C5053g.a), R1.e(k), R1.e(k), R1.e(kSerializerArr[22])};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerializableGBFeatureRule deserialize(@NotNull Decoder decoder) {
        Pair pair;
        int i;
        ArrayList arrayList;
        Pair pair2;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor serialDescriptor = descriptor;
        a aVarC = decoder.c(serialDescriptor);
        KSerializer[] kSerializerArr = SerializableGBFeatureRule.$childSerializers;
        ArrayList arrayList2 = null;
        ArrayList arrayList3 = null;
        List list = null;
        Pair pair3 = null;
        Integer num = null;
        ArrayList arrayList4 = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        Boolean bool = null;
        Integer num2 = null;
        Integer num3 = null;
        String str5 = null;
        k kVar = null;
        ArrayList arrayList5 = null;
        Float f = null;
        OptionalProperty optionalProperty = null;
        List list2 = null;
        String str6 = null;
        List list3 = null;
        d dVar = null;
        String str7 = null;
        int i2 = 0;
        boolean z = true;
        while (z) {
            Integer num4 = num;
            int iT = aVarC.t(serialDescriptor);
            switch (iT) {
                case -1:
                    d dVar2 = dVar;
                    arrayList4 = arrayList4;
                    str = str;
                    arrayList3 = arrayList3;
                    optionalProperty = optionalProperty;
                    list2 = list2;
                    str4 = str4;
                    bool = bool;
                    z = false;
                    dVar = dVar2;
                    num = num4;
                case 0:
                    pair = pair3;
                    boolean z2 = z;
                    i2 |= 1;
                    arrayList4 = arrayList4;
                    str = str;
                    num = num4;
                    arrayList3 = arrayList3;
                    optionalProperty = optionalProperty;
                    list2 = list2;
                    str4 = str4;
                    bool = bool;
                    dVar = dVar;
                    z = z2;
                    str5 = (String) aVarC.v(serialDescriptor, 0, q0.a, str5);
                    pair3 = pair;
                case 1:
                    boolean z3 = z;
                    Boolean bool2 = bool;
                    kVar = (k) aVarC.v(serialDescriptor, 1, m.a, kVar);
                    i2 |= 2;
                    str = str;
                    num = num4;
                    pair3 = pair3;
                    arrayList3 = arrayList3;
                    list2 = list2;
                    bool = bool2;
                    z = z3;
                case 2:
                    arrayList = arrayList3;
                    pair2 = pair3;
                    arrayList5 = (ArrayList) aVarC.v(serialDescriptor, 2, kSerializerArr[2], arrayList5);
                    i2 |= 4;
                    num = num4;
                    pair3 = pair2;
                    arrayList3 = arrayList;
                case 3:
                    arrayList = arrayList3;
                    pair2 = pair3;
                    f = (Float) aVarC.v(serialDescriptor, 3, C.a, f);
                    i2 |= 8;
                    num = num4;
                    pair3 = pair2;
                    arrayList3 = arrayList;
                case 4:
                    arrayList = arrayList3;
                    pair2 = pair3;
                    optionalProperty = (OptionalProperty) aVarC.z(serialDescriptor, 4, kSerializerArr[4], optionalProperty);
                    i2 |= 16;
                    num = num4;
                    pair3 = pair2;
                    arrayList3 = arrayList;
                case 5:
                    arrayList = arrayList3;
                    pair2 = pair3;
                    list2 = (List) aVarC.v(serialDescriptor, 5, kSerializerArr[5], list2);
                    i2 |= 32;
                    num = num4;
                    pair3 = pair2;
                    arrayList3 = arrayList;
                case 6:
                    arrayList = arrayList3;
                    pair2 = pair3;
                    str6 = (String) aVarC.v(serialDescriptor, 6, q0.a, str6);
                    i2 |= 64;
                    num = num4;
                    pair3 = pair2;
                    arrayList3 = arrayList;
                case 7:
                    arrayList = arrayList3;
                    pair2 = pair3;
                    list3 = (List) aVarC.v(serialDescriptor, 7, kSerializerArr[7], list3);
                    i2 |= 128;
                    num = num4;
                    pair3 = pair2;
                    arrayList3 = arrayList;
                case 8:
                    arrayList = arrayList3;
                    pair2 = pair3;
                    dVar = (d) aVarC.v(serialDescriptor, 8, f.a, dVar);
                    i2 |= 256;
                    num = num4;
                    pair3 = pair2;
                    arrayList3 = arrayList;
                case 9:
                    arrayList = arrayList3;
                    pair2 = pair3;
                    str7 = (String) aVarC.v(serialDescriptor, 9, q0.a, str7);
                    i2 |= g.MAX_CONTENT_URL_LENGTH;
                    num = num4;
                    pair3 = pair2;
                    arrayList3 = arrayList;
                case 10:
                    arrayList = arrayList3;
                    pair2 = pair3;
                    num = (Integer) aVarC.v(serialDescriptor, 10, K.a, num4);
                    i2 |= 1024;
                    pair3 = pair2;
                    arrayList3 = arrayList;
                case 11:
                    arrayList = arrayList3;
                    pair3 = (Pair) aVarC.v(serialDescriptor, 11, RangeSerializer.GBBucketRangeSerializer.INSTANCE, pair3);
                    i2 |= 2048;
                    num = num4;
                    arrayList3 = arrayList;
                case 12:
                    pair = pair3;
                    list = (List) aVarC.v(serialDescriptor, 12, RangeSerializer.GBBucketRangeListSerializer.INSTANCE, list);
                    i2 |= 4096;
                    num = num4;
                    pair3 = pair;
                case 13:
                    pair = pair3;
                    arrayList3 = (ArrayList) aVarC.v(serialDescriptor, 13, kSerializerArr[13], arrayList3);
                    i2 |= 8192;
                    num = num4;
                    pair3 = pair;
                case 14:
                    pair = pair3;
                    arrayList4 = (ArrayList) aVarC.v(serialDescriptor, 14, kSerializerArr[14], arrayList4);
                    i2 |= 16384;
                    num = num4;
                    pair3 = pair;
                case 15:
                    pair = pair3;
                    str = (String) aVarC.v(serialDescriptor, 15, q0.a, str);
                    i = 32768;
                    i2 |= i;
                    num = num4;
                    pair3 = pair;
                case 16:
                    pair = pair3;
                    str2 = (String) aVarC.v(serialDescriptor, 16, q0.a, str2);
                    i = 65536;
                    i2 |= i;
                    num = num4;
                    pair3 = pair;
                case 17:
                    pair = pair3;
                    str3 = (String) aVarC.v(serialDescriptor, 17, q0.a, str3);
                    i = 131072;
                    i2 |= i;
                    num = num4;
                    pair3 = pair;
                case 18:
                    pair = pair3;
                    str4 = (String) aVarC.v(serialDescriptor, 18, q0.a, str4);
                    i = 262144;
                    i2 |= i;
                    num = num4;
                    pair3 = pair;
                case 19:
                    pair = pair3;
                    bool = (Boolean) aVarC.v(serialDescriptor, 19, C5053g.a, bool);
                    i = 524288;
                    i2 |= i;
                    num = num4;
                    pair3 = pair;
                case 20:
                    pair = pair3;
                    num2 = (Integer) aVarC.v(serialDescriptor, 20, K.a, num2);
                    i = 1048576;
                    i2 |= i;
                    num = num4;
                    pair3 = pair;
                case 21:
                    pair = pair3;
                    num3 = (Integer) aVarC.v(serialDescriptor, 21, K.a, num3);
                    i = 2097152;
                    i2 |= i;
                    num = num4;
                    pair3 = pair;
                case EventType.WINDOW_STATE /* 22 */:
                    pair = pair3;
                    arrayList2 = (ArrayList) aVarC.v(serialDescriptor, 22, kSerializerArr[22], arrayList2);
                    i = 4194304;
                    i2 |= i;
                    num = num4;
                    pair3 = pair;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        ArrayList arrayList6 = arrayList3;
        Integer num5 = num;
        Boolean bool3 = bool;
        ArrayList arrayList7 = arrayList5;
        List list4 = list2;
        d dVar3 = dVar;
        String str8 = str;
        String str9 = str4;
        k kVar2 = kVar;
        OptionalProperty optionalProperty2 = optionalProperty;
        ArrayList arrayList8 = arrayList4;
        String str10 = str5;
        aVarC.b(serialDescriptor);
        Integer num6 = num3;
        return new SerializableGBFeatureRule(i2, str10, kVar2, arrayList7, f, optionalProperty2, list4, str6, list3, dVar3, str7, num5, pair3, list, arrayList6, arrayList8, str8, str2, str3, str9, bool3, num2, num6, arrayList2, (l0) null);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(@NotNull Encoder encoder, @NotNull SerializableGBFeatureRule value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor serialDescriptor = descriptor;
        b bVarC = encoder.c(serialDescriptor);
        SerializableGBFeatureRule.write$Self$GrowthBook_release(value, bVarC, serialDescriptor);
        bVarC.b(serialDescriptor);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
