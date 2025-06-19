package kotlinx.serialization.json.internal;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.p0;
import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_camera.S1;
import com.google.android.gms.internal.mlkit_vision_camera.U1;
import java.lang.annotation.Annotation;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.SerializationException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.internal.AbstractC5047c0;

/* loaded from: classes3.dex */
public abstract class k {
    public static final l a = new l();

    public static final JsonEncodingException a(Number value, String output) {
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(output, "output");
        return new JsonEncodingException("Unexpected special floating-point value " + value + ". By default, non-finite floating point values are prohibited because they do not conform JSON specification. It is possible to deserialize them using 'JsonBuilder.allowSpecialFloatingPointValues = true'\nCurrent output: " + ((Object) p(-1, output)));
    }

    public static final JsonEncodingException b(SerialDescriptor keyDescriptor) {
        Intrinsics.checkNotNullParameter(keyDescriptor, "keyDescriptor");
        return new JsonEncodingException("Value of type '" + keyDescriptor.a() + "' can't be used in JSON as a key in the map. It should have either primitive or enum kind, but its kind is '" + keyDescriptor.e() + "'.\nUse 'allowStructuredMapKeys = true' in 'Json {}' builder to convert such maps to [key1, value1, key2, value2,...] arrays.");
    }

    public static final JsonDecodingException c(int i, String message) {
        Intrinsics.checkNotNullParameter(message, "message");
        if (i >= 0) {
            message = "Unexpected JSON token at offset " + i + ": " + message;
        }
        return new JsonDecodingException(message);
    }

    public static final JsonDecodingException d(int i, String message, CharSequence input) {
        Intrinsics.checkNotNullParameter(message, "message");
        Intrinsics.checkNotNullParameter(input, "input");
        return c(i, message + "\nJSON input: " + ((Object) p(i, input)));
    }

    public static final androidx.camera.camera2.internal.concurrent.a e(kotlinx.serialization.json.c json, String source) {
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(source, "source");
        kotlinx.serialization.json.i iVar = json.a;
        return new androidx.camera.camera2.internal.concurrent.a(source);
    }

    public static final void f(KSerializer kSerializer, KSerializer kSerializer2, String str) {
        if (kSerializer instanceof kotlinx.serialization.e) {
            SerialDescriptor descriptor = kSerializer2.getDescriptor();
            Intrinsics.checkNotNullParameter(descriptor, "<this>");
            if (AbstractC5047c0.b(descriptor).contains(str)) {
                StringBuilder sbH = AbstractC0147y.h("Sealed class '", kSerializer2.getDescriptor().a(), "' cannot be serialized as base class '", ((kotlinx.serialization.e) kSerializer).getDescriptor().a(), "' because it has property name that conflicts with JSON class discriminator '");
                sbH.append(str);
                sbH.append("'. You can either change class discriminator in JsonConfiguration, rename property with @SerialName annotation or fall back to array polymorphism");
                throw new IllegalStateException(sbH.toString().toString());
            }
        }
    }

    public static final SerialDescriptor g(SerialDescriptor descriptor, p0 module) {
        SerialDescriptor serialDescriptorG;
        KSerializer kSerializerI;
        Intrinsics.checkNotNullParameter(descriptor, "<this>");
        Intrinsics.checkNotNullParameter(module, "module");
        if (!Intrinsics.b(descriptor.e(), kotlinx.serialization.descriptors.h.b)) {
            return descriptor.isInline() ? g(descriptor.i(0), module) : descriptor;
        }
        Intrinsics.checkNotNullParameter(module, "<this>");
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        kotlin.reflect.c cVarB = S1.b(descriptor);
        SerialDescriptor descriptor2 = null;
        if (cVarB != null && (kSerializerI = module.i(cVarB, K.a)) != null) {
            descriptor2 = kSerializerI.getDescriptor();
        }
        return (descriptor2 == null || (serialDescriptorG = g(descriptor2, module)) == null) ? descriptor : serialDescriptorG;
    }

    public static final byte h(char c) {
        if (c < '~') {
            return e.b[c];
        }
        return (byte) 0;
    }

    public static final void i(U1 kind) {
        Intrinsics.checkNotNullParameter(kind, "kind");
        if (kind instanceof kotlinx.serialization.descriptors.i) {
            throw new IllegalStateException("Enums cannot be serialized polymorphically with 'type' parameter. You can use 'JsonBuilder.useArrayPolymorphism' instead");
        }
        if (kind instanceof kotlinx.serialization.descriptors.f) {
            throw new IllegalStateException("Primitives cannot be serialized polymorphically with 'type' parameter. You can use 'JsonBuilder.useArrayPolymorphism' instead");
        }
        if (kind instanceof kotlinx.serialization.descriptors.d) {
            throw new IllegalStateException("Actual serializer for polymorphic cannot be polymorphic itself");
        }
    }

    public static final String j(SerialDescriptor serialDescriptor, kotlinx.serialization.json.c json) {
        Intrinsics.checkNotNullParameter(serialDescriptor, "<this>");
        Intrinsics.checkNotNullParameter(json, "json");
        for (Annotation annotation : serialDescriptor.getAnnotations()) {
            if (annotation instanceof kotlinx.serialization.json.h) {
                return ((kotlinx.serialization.json.h) annotation).discriminator();
            }
        }
        return json.a.g;
    }

    public static final void k(kotlinx.serialization.json.c json, com.android.billingclient.api.s sb, KSerializer serializer, Object obj) {
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(sb, "writer");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        y mode = y.c;
        kotlinx.serialization.json.o[] modeReuseCache = new kotlinx.serialization.json.o[y.h.a()];
        Intrinsics.checkNotNullParameter(sb, "output");
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(mode, "mode");
        Intrinsics.checkNotNullParameter(modeReuseCache, "modeReuseCache");
        Intrinsics.checkNotNullParameter(sb, "sb");
        Intrinsics.checkNotNullParameter(json, "json");
        new v(json.a.d ? new h(sb, json) : new androidx.appcompat.app.K(sb), json, mode, modeReuseCache).y(serializer, obj);
    }

    public static final int l(SerialDescriptor descriptor, kotlinx.serialization.json.c json, String name) {
        Intrinsics.checkNotNullParameter(descriptor, "<this>");
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(name, "name");
        kotlinx.serialization.json.i iVar = json.a;
        q(descriptor, json);
        int iD = descriptor.d(name);
        if (iD != -3 || !json.a.i) {
            return iD;
        }
        Intrinsics.checkNotNullParameter(json, "<this>");
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(json, "<this>");
        l key = a;
        com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v defaultValue = new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v(15, descriptor, json);
        com.quizlet.quizletandroid.ui.login.h hVar = json.c;
        hVar.getClass();
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(defaultValue, "defaultValue");
        Object value = hVar.d(descriptor, key);
        if (value == null) {
            value = defaultValue.invoke();
            Intrinsics.checkNotNullParameter(descriptor, "descriptor");
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(value, "value");
            ConcurrentHashMap concurrentHashMap = (ConcurrentHashMap) hVar.b;
            Object concurrentHashMap2 = concurrentHashMap.get(descriptor);
            if (concurrentHashMap2 == null) {
                concurrentHashMap2 = new ConcurrentHashMap(2);
                concurrentHashMap.put(descriptor, concurrentHashMap2);
            }
            ((Map) concurrentHashMap2).put(key, value);
        }
        Integer num = (Integer) ((Map) value).get(name);
        if (num != null) {
            return num.intValue();
        }
        return -3;
    }

    public static final int m(SerialDescriptor serialDescriptor, kotlinx.serialization.json.c json, String name, String suffix) {
        Intrinsics.checkNotNullParameter(serialDescriptor, "<this>");
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(suffix, "suffix");
        int iL = l(serialDescriptor, json, name);
        if (iL != -3) {
            return iL;
        }
        throw new SerializationException(serialDescriptor.a() + " does not contain element with name '" + name + '\'' + suffix);
    }

    public static final boolean n(SerialDescriptor serialDescriptor, kotlinx.serialization.json.c json) {
        Intrinsics.checkNotNullParameter(serialDescriptor, "<this>");
        Intrinsics.checkNotNullParameter(json, "json");
        if (json.a.b) {
            return true;
        }
        List annotations = serialDescriptor.getAnnotations();
        if (annotations != null && annotations.isEmpty()) {
            return false;
        }
        Iterator it2 = annotations.iterator();
        while (it2.hasNext()) {
            if (((Annotation) it2.next()) instanceof kotlinx.serialization.json.p) {
                return true;
            }
        }
        return false;
    }

    public static final void o(androidx.camera.camera2.internal.concurrent.a aVar, String entity) {
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        Intrinsics.checkNotNullParameter(entity, "entity");
        aVar.q(aVar.b - 1, "Trailing comma before the end of JSON ".concat(entity), "Trailing commas are non-complaint JSON and not allowed by default. Use 'allowTrailingComma = true' in 'Json {}' builder to support them.");
        throw null;
    }

    public static final CharSequence p(int i, CharSequence charSequence) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        if (charSequence.length() >= 200) {
            if (i != -1) {
                int i2 = i - 30;
                int i3 = i + 30;
                String str = i2 <= 0 ? "" : ".....";
                String str2 = i3 >= charSequence.length() ? "" : ".....";
                StringBuilder sbU = d0.u(str);
                if (i2 < 0) {
                    i2 = 0;
                }
                int length = charSequence.length();
                if (i3 > length) {
                    i3 = length;
                }
                sbU.append(charSequence.subSequence(i2, i3).toString());
                sbU.append(str2);
                return sbU.toString();
            }
            int length2 = charSequence.length() - 60;
            if (length2 > 0) {
                return "....." + charSequence.subSequence(length2, charSequence.length()).toString();
            }
        }
        return charSequence;
    }

    public static final void q(SerialDescriptor serialDescriptor, kotlinx.serialization.json.c json) {
        Intrinsics.checkNotNullParameter(serialDescriptor, "<this>");
        Intrinsics.checkNotNullParameter(json, "json");
        if (Intrinsics.b(serialDescriptor.e(), kotlinx.serialization.descriptors.j.b)) {
            kotlinx.serialization.json.i iVar = json.a;
        }
    }

    public static final Object r(kotlinx.serialization.json.c cVar, String discriminator, kotlinx.serialization.json.v element, KSerializer deserializer) {
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        Intrinsics.checkNotNullParameter(discriminator, "discriminator");
        Intrinsics.checkNotNullParameter(element, "element");
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        return new o(cVar, element, discriminator, deserializer.getDescriptor()).u(deserializer);
    }

    public static final y s(SerialDescriptor desc, kotlinx.serialization.json.c cVar) {
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        Intrinsics.checkNotNullParameter(desc, "desc");
        U1 u1E = desc.e();
        if (u1E instanceof kotlinx.serialization.descriptors.d) {
            return y.f;
        }
        if (Intrinsics.b(u1E, kotlinx.serialization.descriptors.j.c)) {
            return y.d;
        }
        if (!Intrinsics.b(u1E, kotlinx.serialization.descriptors.j.d)) {
            return y.c;
        }
        SerialDescriptor serialDescriptorG = g(desc.i(0), cVar.b);
        U1 u1E2 = serialDescriptorG.e();
        if ((u1E2 instanceof kotlinx.serialization.descriptors.f) || Intrinsics.b(u1E2, kotlinx.serialization.descriptors.i.b)) {
            return y.e;
        }
        throw b(serialDescriptorG);
    }

    public static final void t(androidx.camera.camera2.internal.concurrent.a aVar, Number result) {
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        Intrinsics.checkNotNullParameter(result, "result");
        androidx.camera.camera2.internal.concurrent.a.r(aVar, "Unexpected special floating-point value " + result + ". By default, non-finite floating point values are prohibited because they do not conform JSON specification", 0, "It is possible to deserialize them using 'JsonBuilder.allowSpecialFloatingPointValues = true'", 2);
        throw null;
    }

    public static final String u(byte b) {
        return b == 1 ? "quotation mark '\"'" : b == 2 ? "string escape sequence '\\'" : b == 4 ? "comma ','" : b == 5 ? "colon ':'" : b == 6 ? "start of the object '{'" : b == 7 ? "end of the object '}'" : b == 8 ? "start of the array '['" : b == 9 ? "end of the array ']'" : b == 10 ? "end of the input" : b == Byte.MAX_VALUE ? "invalid token" : "valid token";
    }

    public static final String v(Number number, String str, String str2) {
        return "Unexpected special floating-point value " + number + " with key " + str + ". By default, non-finite floating point values are prohibited because they do not conform JSON specification. It is possible to deserialize them using 'JsonBuilder.allowSpecialFloatingPointValues = true'\nCurrent output: " + ((Object) p(-1, str2));
    }
}
