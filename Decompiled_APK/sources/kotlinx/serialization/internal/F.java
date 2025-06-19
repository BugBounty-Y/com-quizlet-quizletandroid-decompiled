package kotlinx.serialization.internal;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public final class F extends AbstractC5042a {
    public final KSerializer a;
    public final KSerializer b;
    public final /* synthetic */ int c;
    public final E d;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public F(KSerializer kSerializer, KSerializer vSerializer, int i) {
        this(kSerializer, vSerializer, (byte) 0);
        this.c = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(kSerializer, "kSerializer");
                Intrinsics.checkNotNullParameter(vSerializer, "vSerializer");
                this(kSerializer, vSerializer, (byte) 0);
                SerialDescriptor keyDesc = kSerializer.getDescriptor();
                SerialDescriptor valueDesc = vSerializer.getDescriptor();
                Intrinsics.checkNotNullParameter(keyDesc, "keyDesc");
                Intrinsics.checkNotNullParameter(valueDesc, "valueDesc");
                this.d = new E("kotlin.collections.LinkedHashMap", keyDesc, valueDesc);
                break;
            default:
                Intrinsics.checkNotNullParameter(kSerializer, "kSerializer");
                Intrinsics.checkNotNullParameter(vSerializer, "vSerializer");
                SerialDescriptor keyDesc2 = kSerializer.getDescriptor();
                SerialDescriptor valueDesc2 = vSerializer.getDescriptor();
                Intrinsics.checkNotNullParameter(keyDesc2, "keyDesc");
                Intrinsics.checkNotNullParameter(valueDesc2, "valueDesc");
                this.d = new E("kotlin.collections.HashMap", keyDesc2, valueDesc2);
                break;
        }
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object a() {
        switch (this.c) {
            case 0:
                return new HashMap();
            default:
                return new LinkedHashMap();
        }
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int b(Object obj) {
        switch (this.c) {
            case 0:
                HashMap map = (HashMap) obj;
                Intrinsics.checkNotNullParameter(map, "<this>");
                return map.size() * 2;
            default:
                LinkedHashMap linkedHashMap = (LinkedHashMap) obj;
                Intrinsics.checkNotNullParameter(linkedHashMap, "<this>");
                return linkedHashMap.size() * 2;
        }
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Iterator c(Object obj) {
        switch (this.c) {
            case 0:
                Map map = (Map) obj;
                Intrinsics.checkNotNullParameter(map, "<this>");
                return map.entrySet().iterator();
            default:
                Map map2 = (Map) obj;
                Intrinsics.checkNotNullParameter(map2, "<this>");
                return map2.entrySet().iterator();
        }
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int d(Object obj) {
        switch (this.c) {
            case 0:
                Map map = (Map) obj;
                Intrinsics.checkNotNullParameter(map, "<this>");
                return map.size();
            default:
                Map map2 = (Map) obj;
                Intrinsics.checkNotNullParameter(map2, "<this>");
                return map2.size();
        }
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final void f(kotlinx.serialization.encoding.a decoder, int i, Object obj) {
        Map builder = (Map) obj;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        Intrinsics.checkNotNullParameter(builder, "builder");
        Object objZ = decoder.z(getDescriptor(), i, this.a, null);
        int iT = decoder.t(getDescriptor());
        if (iT != i + 1) {
            throw new IllegalArgumentException(androidx.compose.animation.d0.p("Value must follow key in a map, index for key: ", i, ", returned index for value: ", iT).toString());
        }
        boolean zContainsKey = builder.containsKey(objZ);
        KSerializer kSerializer = this.b;
        builder.put(objZ, (!zContainsKey || (kSerializer.getDescriptor().e() instanceof kotlinx.serialization.descriptors.f)) ? decoder.z(getDescriptor(), iT, kSerializer, null) : decoder.z(getDescriptor(), iT, kSerializer, kotlin.collections.V.d(objZ, builder)));
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object g(Object obj) {
        switch (this.c) {
            case 0:
                Intrinsics.checkNotNullParameter(null, "<this>");
                return new HashMap((Map) null);
            default:
                Intrinsics.checkNotNullParameter(null, "<this>");
                return new LinkedHashMap((Map) null);
        }
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        switch (this.c) {
        }
        return this.d;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object h(Object obj) {
        switch (this.c) {
            case 0:
                HashMap map = (HashMap) obj;
                Intrinsics.checkNotNullParameter(map, "<this>");
                return map;
            default:
                LinkedHashMap linkedHashMap = (LinkedHashMap) obj;
                Intrinsics.checkNotNullParameter(linkedHashMap, "<this>");
                return linkedHashMap;
        }
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        d(obj);
        SerialDescriptor descriptor = getDescriptor();
        kotlinx.serialization.encoding.b bVarZ = encoder.z(descriptor);
        Iterator itC = c(obj);
        int i = 0;
        while (itC.hasNext()) {
            Map.Entry entry = (Map.Entry) itC.next();
            Object key = entry.getKey();
            Object value = entry.getValue();
            int i2 = i + 1;
            bVarZ.i(getDescriptor(), i, this.a, key);
            i += 2;
            bVarZ.i(getDescriptor(), i2, this.b, value);
        }
        bVarZ.b(descriptor);
    }

    public F(KSerializer kSerializer, KSerializer kSerializer2, byte b) {
        this.a = kSerializer;
        this.b = kSerializer2;
    }
}
