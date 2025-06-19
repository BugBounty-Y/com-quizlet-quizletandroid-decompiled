package kotlinx.serialization.internal;

import com.google.android.gms.internal.mlkit_vision_camera.O1;
import java.util.Map;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.SerializationException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;

/* renamed from: kotlinx.serialization.internal.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC5044b implements KSerializer {
    /* JADX WARN: Type inference failed for: r1v1, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r4v2, types: [java.lang.Object, java.util.Map] */
    public KSerializer a(kotlinx.serialization.encoding.a decoder, String str) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        androidx.camera.camera2.internal.p0 p0VarA = decoder.a();
        kotlin.reflect.c baseClass = c();
        p0VarA.getClass();
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        Map map = (Map) p0VarA.e.get(baseClass);
        KSerializer kSerializer = map != null ? (KSerializer) map.get(str) : null;
        if (kSerializer == null) {
            kSerializer = null;
        }
        if (kSerializer != null) {
            return kSerializer;
        }
        Object obj = p0VarA.f.get(baseClass);
        Function1 function1 = kotlin.jvm.internal.O.e(1, obj) ? (Function1) obj : null;
        if (function1 != null) {
            return (KSerializer) function1.invoke(str);
        }
        return null;
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r5v2, types: [java.lang.Object, java.util.Map] */
    public KSerializer b(Encoder encoder, Object value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        androidx.camera.camera2.internal.p0 p0VarA = encoder.a();
        kotlin.reflect.c baseClass = c();
        p0VarA.getClass();
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        Intrinsics.checkNotNullParameter(value, "value");
        C4950i c4950i = (C4950i) baseClass;
        if (c4950i.g(value)) {
            Map map = (Map) p0VarA.d.get(c4950i);
            KSerializer kSerializer = map != null ? (KSerializer) map.get(kotlin.jvm.internal.K.a(value.getClass())) : null;
            if (kSerializer == null) {
                kSerializer = null;
            }
            if (kSerializer != null) {
                return kSerializer;
            }
            Object obj = p0VarA.a.get(c4950i);
            Function1 function1 = kotlin.jvm.internal.O.e(1, obj) ? (Function1) obj : null;
            if (function1 != null) {
                return (KSerializer) function1.invoke(value);
            }
        }
        return null;
    }

    public abstract kotlin.reflect.c c();

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor);
        kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
        Object objZ = null;
        while (true) {
            int iT = aVarC.t(getDescriptor());
            if (iT == -1) {
                if (objZ != null) {
                    aVarC.b(descriptor);
                    return objZ;
                }
                throw new IllegalArgumentException(("Polymorphic value has not been read for class " + ((String) j.a)).toString());
            }
            if (iT == 0) {
                j.a = aVarC.r(getDescriptor(), iT);
            } else {
                if (iT != 1) {
                    StringBuilder sb = new StringBuilder("Invalid index in polymorphic deserialization of ");
                    String str = (String) j.a;
                    if (str == null) {
                        str = "unknown class";
                    }
                    sb.append(str);
                    sb.append("\n Expected 0, 1 or DECODE_DONE(-1), but found ");
                    sb.append(iT);
                    throw new SerializationException(sb.toString());
                }
                Object obj = j.a;
                if (obj == null) {
                    throw new IllegalArgumentException("Cannot read polymorphic value before its type token");
                }
                j.a = obj;
                objZ = aVarC.z(getDescriptor(), iT, O1.b(this, aVarC, (String) obj), null);
            }
        }
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        KSerializer kSerializerC = O1.c(this, encoder, value);
        SerialDescriptor descriptor = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor);
        bVarC.r(getDescriptor(), 0, kSerializerC.getDescriptor().a());
        bVarC.i(getDescriptor(), 1, kSerializerC, value);
        bVarC.b(descriptor);
    }
}
