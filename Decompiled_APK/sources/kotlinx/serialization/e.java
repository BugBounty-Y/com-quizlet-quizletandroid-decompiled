package kotlinx.serialization;

import com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v;
import java.lang.annotation.Annotation;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.collections.C4930v;
import kotlin.collections.C4933y;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.m;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.AbstractC5044b;

/* loaded from: classes3.dex */
public final class e extends AbstractC5044b {
    public final C4950i a;
    public final List b;
    public final Object c;
    public final Map d;
    public final LinkedHashMap e;

    public e(String serialName, C4950i baseClass, kotlin.reflect.c[] subclasses, KSerializer[] subclassSerializers, Annotation[] classAnnotations) {
        Intrinsics.checkNotNullParameter(serialName, "serialName");
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        Intrinsics.checkNotNullParameter(subclasses, "subclasses");
        Intrinsics.checkNotNullParameter(subclassSerializers, "subclassSerializers");
        Intrinsics.checkNotNullParameter(classAnnotations, "classAnnotations");
        Intrinsics.checkNotNullParameter(serialName, "serialName");
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        Intrinsics.checkNotNullParameter(subclasses, "subclasses");
        Intrinsics.checkNotNullParameter(subclassSerializers, "subclassSerializers");
        this.a = baseClass;
        this.b = K.a;
        this.c = l.a(m.b, new v(12, serialName, this));
        if (subclasses.length != subclassSerializers.length) {
            throw new IllegalArgumentException("All subclasses of sealed class " + baseClass.f() + " should be marked @Serializable");
        }
        Map mapK = V.k(C4933y.U(subclasses, subclassSerializers));
        this.d = mapK;
        Set<Map.Entry> setEntrySet = mapK.entrySet();
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Map.Entry entry : setEntrySet) {
            String strA = ((KSerializer) entry.getValue()).getDescriptor().a();
            Object obj = linkedHashMap.get(strA);
            if (obj == null) {
                linkedHashMap.containsKey(strA);
            }
            Map.Entry entry2 = (Map.Entry) obj;
            if (entry2 != null) {
                throw new IllegalStateException(("Multiple sealed subclasses of '" + this.a + "' have the same serial name '" + strA + "': '" + entry2.getKey() + "', '" + entry.getKey() + '\'').toString());
            }
            linkedHashMap.put(strA, entry);
        }
        LinkedHashMap linkedHashMap2 = new LinkedHashMap(U.a(linkedHashMap.size()));
        for (Map.Entry entry3 : linkedHashMap.entrySet()) {
            linkedHashMap2.put(entry3.getKey(), (KSerializer) ((Map.Entry) entry3.getValue()).getValue());
        }
        this.e = linkedHashMap2;
        this.b = C4930v.c(classAnnotations);
    }

    @Override // kotlinx.serialization.internal.AbstractC5044b
    public final KSerializer a(kotlinx.serialization.encoding.a decoder, String str) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        KSerializer kSerializer = (KSerializer) this.e.get(str);
        return kSerializer != null ? kSerializer : super.a(decoder, str);
    }

    @Override // kotlinx.serialization.internal.AbstractC5044b
    public final KSerializer b(Encoder encoder, Object value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        KSerializer kSerializerB = (KSerializer) this.d.get(kotlin.jvm.internal.K.a(value.getClass()));
        if (kSerializerB == null) {
            kSerializerB = super.b(encoder, value);
        }
        if (kSerializerB != null) {
            return kSerializerB;
        }
        return null;
    }

    @Override // kotlinx.serialization.internal.AbstractC5044b
    public final kotlin.reflect.c c() {
        return this.a;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, kotlin.k] */
    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        return (SerialDescriptor) this.c.getValue();
    }
}
