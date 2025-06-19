package kotlinx.serialization.json;

import com.google.android.gms.internal.mlkit_vision_camera.T1;
import com.google.android.gms.internal.mlkit_vision_camera.X1;
import kotlin.D;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.text.C;
import kotlin.text.J;
import kotlin.text.StringsKt;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.h0;
import kotlinx.serialization.internal.z0;

/* loaded from: classes3.dex */
public final class s implements KSerializer {
    public static final s a = new s();
    public static final h0 b = T1.c("kotlinx.serialization.json.JsonLiteral", kotlinx.serialization.descriptors.e.j);

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        k kVarL = X1.d(decoder).l();
        if (kVarL instanceof r) {
            return (r) kVarL;
        }
        throw kotlinx.serialization.json.internal.k.d(-1, "Unexpected JSON element, expected JsonLiteral, had " + K.a(kVarL.getClass()), kVarL.toString());
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        return b;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        r value = (r) obj;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        X1.c(encoder);
        boolean z = value.a;
        String str = value.c;
        if (z) {
            encoder.E(str);
            return;
        }
        SerialDescriptor serialDescriptor = value.b;
        if (serialDescriptor != null) {
            encoder.x(serialDescriptor).E(str);
            return;
        }
        Long lF0 = StringsKt.f0(str);
        if (lF0 != null) {
            encoder.B(lF0.longValue());
            return;
        }
        D dH = J.h(str);
        if (dH != null) {
            Intrinsics.checkNotNullParameter(D.b, "<this>");
            encoder.x(z0.b).B(dH.a);
            return;
        }
        Double dE = C.e(str);
        if (dE != null) {
            encoder.e(dE.doubleValue());
            return;
        }
        Intrinsics.checkNotNullParameter(str, "<this>");
        Boolean bool = str.equals("true") ? Boolean.TRUE : str.equals("false") ? Boolean.FALSE : null;
        if (bool != null) {
            encoder.k(bool.booleanValue());
        } else {
            encoder.E(str);
        }
    }
}
