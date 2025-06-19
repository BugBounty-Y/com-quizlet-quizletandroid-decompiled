package com.sdk.growthbook.utils;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.google.android.gms.internal.mlkit_vision_camera.T1;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.B;
import kotlin.jvm.internal.C4952k;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.C;
import kotlinx.serialization.internal.C5046c;
import kotlinx.serialization.internal.G;
import kotlinx.serialization.internal.Q;
import kotlinx.serialization.internal.T;
import kotlinx.serialization.json.d;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.l;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RangeSerializer {

    @NotNull
    public static final RangeSerializer INSTANCE = new RangeSerializer();

    @Metadata
    public static final class GBBucketRangeListSerializer implements KSerializer {

        @NotNull
        public static final GBBucketRangeListSerializer INSTANCE = new GBBucketRangeListSerializer();

        @NotNull
        private static final SerialDescriptor descriptor;

        static {
            C4952k c4952k = C4952k.a;
            R1.f(c4952k);
            C valueSerializer = C.a;
            Intrinsics.checkNotNullParameter(c4952k, "<this>");
            Intrinsics.checkNotNullParameter(valueSerializer, "keySerializer");
            Intrinsics.checkNotNullParameter(valueSerializer, "valueSerializer");
            descriptor = (C5046c) R1.a(new T(valueSerializer, valueSerializer, 1)).c;
        }

        private GBBucketRangeListSerializer() {
        }

        @Override // kotlinx.serialization.KSerializer
        @NotNull
        public SerialDescriptor getDescriptor() {
            return descriptor;
        }

        @Override // kotlinx.serialization.KSerializer
        @NotNull
        public List<Pair<Float, Float>> deserialize(@NotNull Decoder decoder) {
            Intrinsics.checkNotNullParameter(decoder, "decoder");
            d dVar = (d) decoder.u(d.Companion.serializer());
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(dVar, 10));
            for (k kVar : dVar.a) {
                G g = l.a;
                Intrinsics.checkNotNullParameter(kVar, "<this>");
                d dVar2 = kVar instanceof d ? (d) kVar : null;
                if (dVar2 == null) {
                    l.d("JsonArray", kVar);
                    throw null;
                }
                Float f = l.f(l.h(dVar2.get(0)));
                Intrinsics.checkNotNullParameter(kVar, "<this>");
                d dVar3 = kVar instanceof d ? (d) kVar : null;
                if (dVar3 == null) {
                    l.d("JsonArray", kVar);
                    throw null;
                }
                Float f2 = l.f(l.h(dVar3.get(1)));
                if (f == null || f2 == null) {
                    throw new IllegalArgumentException("Invalid range format");
                }
                arrayList.add(new Pair(f, f2));
            }
            return arrayList;
        }

        @Override // kotlinx.serialization.KSerializer
        public void serialize(@NotNull Encoder encoder, @NotNull List<Pair<Float, Float>> value) {
            Intrinsics.checkNotNullParameter(encoder, "encoder");
            Intrinsics.checkNotNullParameter(value, "value");
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(value, 10));
            Iterator<T> it2 = value.iterator();
            while (it2.hasNext()) {
                Pair pair = (Pair) it2.next();
                arrayList.add(new d(B.j(l.b((Number) pair.a), l.b((Number) pair.b))));
            }
            encoder.y(d.Companion.serializer(), new d(arrayList));
        }
    }

    @Metadata
    public static final class GBBucketRangeSerializer implements KSerializer {

        @NotNull
        public static final GBBucketRangeSerializer INSTANCE = new GBBucketRangeSerializer();

        @NotNull
        private static final SerialDescriptor descriptor;

        static {
            C4952k c4952k = C4952k.a;
            R1.f(c4952k);
            C valueSerializer = C.a;
            Intrinsics.checkNotNullParameter(c4952k, "<this>");
            Intrinsics.checkNotNullParameter(valueSerializer, "keySerializer");
            Intrinsics.checkNotNullParameter(valueSerializer, "valueSerializer");
            Intrinsics.checkNotNullParameter(valueSerializer, "keySerializer");
            Intrinsics.checkNotNullParameter(valueSerializer, "valueSerializer");
            descriptor = T1.f("kotlin.Pair", new SerialDescriptor[0], new Q(valueSerializer, valueSerializer, 1));
        }

        private GBBucketRangeSerializer() {
        }

        @Override // kotlinx.serialization.KSerializer
        @NotNull
        public SerialDescriptor getDescriptor() {
            return descriptor;
        }

        @Override // kotlinx.serialization.KSerializer
        @NotNull
        public Pair<Float, Float> deserialize(@NotNull Decoder decoder) {
            Intrinsics.checkNotNullParameter(decoder, "decoder");
            d dVar = (d) decoder.u(d.Companion.serializer());
            Float f = l.f(l.h(dVar.get(0)));
            Float f2 = l.f(l.h(dVar.get(1)));
            if (f == null || f2 == null) {
                throw new IllegalArgumentException("Invalid range format");
            }
            return new Pair<>(f, f2);
        }

        @Override // kotlinx.serialization.KSerializer
        public void serialize(@NotNull Encoder encoder, @NotNull Pair<Float, Float> value) {
            Intrinsics.checkNotNullParameter(encoder, "encoder");
            Intrinsics.checkNotNullParameter(value, "value");
            encoder.y(d.Companion.serializer(), new d(B.j(l.b((Number) value.a), l.b((Number) value.b))));
        }
    }

    private RangeSerializer() {
    }
}
