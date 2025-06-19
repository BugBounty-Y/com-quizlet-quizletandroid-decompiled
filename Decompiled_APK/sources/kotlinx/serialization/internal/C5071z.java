package kotlinx.serialization.internal;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import java.util.Arrays;
import java.util.Collection;
import kotlin.collections.C4927s;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.SerializationException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;

/* renamed from: kotlinx.serialization.internal.z, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5071z implements KSerializer {
    public final /* synthetic */ int a = 0;
    public final Object b;
    public final Object c;

    public C5071z(T elementSerializer) {
        Intrinsics.checkNotNullParameter(elementSerializer, "elementSerializer");
        C5048d c5048dA = R1.a(elementSerializer);
        this.b = c5048dA;
        Intrinsics.checkNotNullParameter("ArrayDeque", "serialName");
        C5046c original = (C5046c) c5048dA.c;
        Intrinsics.checkNotNullParameter(original, "original");
        if (StringsKt.O("ArrayDeque")) {
            throw new IllegalArgumentException("Blank serial names are prohibited");
        }
        original.getClass();
        kotlinx.serialization.descriptors.j jVar = kotlinx.serialization.descriptors.j.c;
        this.c = new kotlinx.serialization.descriptors.l(original);
    }

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(decoder, "decoder");
                int i = decoder.i(getDescriptor());
                Enum[] enumArr = (Enum[]) this.b;
                if (i >= 0 && i < enumArr.length) {
                    return enumArr[i];
                }
                throw new SerializationException(i + " is not among valid " + getDescriptor().a() + " enum values, values size is " + enumArr.length);
            default:
                Intrinsics.checkNotNullParameter(decoder, "decoder");
                return new C4927s((Collection) decoder.u((C5048d) this.b));
        }
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        switch (this.a) {
            case 0:
                return (SerialDescriptor) ((kotlin.u) this.c).getValue();
            default:
                return (kotlinx.serialization.descriptors.l) this.c;
        }
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        switch (this.a) {
            case 0:
                Enum value = (Enum) obj;
                Intrinsics.checkNotNullParameter(encoder, "encoder");
                Intrinsics.checkNotNullParameter(value, "value");
                Enum[] enumArr = (Enum[]) this.b;
                int iG = C4933y.G(value, enumArr);
                if (iG != -1) {
                    encoder.v(getDescriptor(), iG);
                    return;
                }
                StringBuilder sb = new StringBuilder();
                sb.append(value);
                sb.append(" is not a valid enum ");
                sb.append(getDescriptor().a());
                sb.append(", must be one of ");
                String string = Arrays.toString(enumArr);
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                sb.append(string);
                throw new SerializationException(sb.toString());
            default:
                C4927s value2 = (C4927s) obj;
                Intrinsics.checkNotNullParameter(encoder, "encoder");
                Intrinsics.checkNotNullParameter(value2, "value");
                encoder.y((C5048d) this.b, CollectionsKt.w0(value2));
                return;
        }
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return "kotlinx.serialization.internal.EnumSerializer<" + getDescriptor().a() + '>';
            default:
                return super.toString();
        }
    }

    public C5071z(String serialName, Enum[] values) {
        Intrinsics.checkNotNullParameter(serialName, "serialName");
        Intrinsics.checkNotNullParameter(values, "values");
        this.b = values;
        this.c = kotlin.l.b(new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v(13, this, serialName));
    }
}
