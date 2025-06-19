package kotlinx.serialization.internal;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3397u1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;

/* renamed from: kotlinx.serialization.internal.w, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5068w implements KSerializer {
    public static final C5068w a = new C5068w();
    public static final h0 b = new h0("kotlin.time.Duration", kotlinx.serialization.descriptors.e.j);

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        kotlin.time.a aVar = kotlin.time.b.b;
        String value = decoder.o();
        aVar.getClass();
        Intrinsics.checkNotNullParameter(value, "value");
        try {
            return new kotlin.time.b(AbstractC3397u1.a(value));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.B("Invalid ISO duration string format: '", value, "'."), e);
        }
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        return b;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        long j;
        int i;
        long j2 = ((kotlin.time.b) obj).a;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        kotlin.time.a aVar = kotlin.time.b.b;
        StringBuilder sb = new StringBuilder();
        if (j2 < 0) {
            sb.append('-');
        }
        sb.append("PT");
        long jK = j2 < 0 ? kotlin.time.b.k(j2) : j2;
        long jI = kotlin.time.b.i(jK, kotlin.time.d.f);
        boolean z = false;
        if (kotlin.time.b.g(jK)) {
            j = 0;
            i = 0;
        } else {
            j = 0;
            i = (int) (kotlin.time.b.i(jK, kotlin.time.d.e) % 60);
        }
        int i2 = kotlin.time.b.g(jK) ? 0 : (int) (kotlin.time.b.i(jK, kotlin.time.d.d) % 60);
        int iF = kotlin.time.b.f(jK);
        if (kotlin.time.b.g(j2)) {
            jI = 9999999999999L;
        }
        boolean z2 = jI != j;
        boolean z3 = (i2 == 0 && iF == 0) ? false : true;
        if (i != 0 || (z3 && z2)) {
            z = true;
        }
        if (z2) {
            sb.append(jI);
            sb.append('H');
        }
        if (z) {
            sb.append(i);
            sb.append('M');
        }
        if (z3 || (!z2 && !z)) {
            kotlin.time.b.b(sb, i2, iF, 9, "S", true);
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        encoder.E(string);
    }
}
