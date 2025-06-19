package serialization;

import android.graphics.ColorSpace;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.mlkit_vision_camera.T1;
import java.util.ArrayList;
import java.util.Arrays;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.h0;

/* loaded from: classes3.dex */
public abstract class a implements KSerializer {
    public final /* synthetic */ int a;
    public final String b;
    public final Enum[] c;
    public final ArrayList d;
    public final h0 e;

    /* JADX WARN: Multi-variable type inference failed */
    public a(String serialName, Enum[] values, int i) {
        this.a = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(serialName, "serialName");
                Intrinsics.checkNotNullParameter(values, "values");
                this.b = serialName;
                this.c = values;
                ArrayList arrayList = new ArrayList(values.length);
                for (ColorSpace.Named named : values) {
                    String value = ((f) named).getValue();
                    if (value == null) {
                        value = named.name();
                    }
                    arrayList.add(value);
                }
                this.d = arrayList;
                this.e = T1.c(this.b, kotlinx.serialization.descriptors.e.j);
                return;
            default:
                Intrinsics.checkNotNullParameter(serialName, "serialName");
                Intrinsics.checkNotNullParameter(values, "choices");
                this.b = serialName;
                this.c = values;
                ArrayList arrayList2 = new ArrayList(values.length);
                for (Object[] objArr : values) {
                    arrayList2.add(Integer.valueOf(((b) objArr).getValue().intValue()));
                }
                this.d = arrayList2;
                this.e = T1.c(this.b, kotlinx.serialization.descriptors.e.g);
                if (arrayList2.size() != this.c.length) {
                    throw new IllegalArgumentException("There must be exactly one serial number for every enum constant.");
                }
                if (CollectionsKt.G(arrayList2).size() != arrayList2.size()) {
                    throw new IllegalArgumentException("There must be no duplicates of serial numbers.");
                }
                return;
        }
    }

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(decoder, "decoder");
                int iM = decoder.m();
                ArrayList arrayList = this.d;
                int iIndexOf = arrayList.indexOf(Integer.valueOf(iM));
                String str = this.b;
                if (iIndexOf == -1) {
                    throw new IllegalStateException((iM + " is not a valid serial value of " + str + ", choices are " + arrayList).toString());
                }
                Enum[] enumArr = this.c;
                if (iIndexOf >= 0 && iIndexOf < enumArr.length) {
                    return enumArr[iIndexOf];
                }
                throw new IllegalStateException((iIndexOf + " is not among valid " + str + " choices, choices size is " + enumArr.length).toString());
            default:
                Intrinsics.checkNotNullParameter(decoder, "decoder");
                String strO = decoder.o();
                ArrayList arrayList2 = this.d;
                int iIndexOf2 = arrayList2.indexOf(strO);
                String str2 = this.b;
                if (iIndexOf2 == -1) {
                    throw new IllegalStateException((strO + " is not a valid serial value of " + str2 + ", values are " + arrayList2).toString());
                }
                Enum[] enumArr2 = this.c;
                if (iIndexOf2 >= 0 && iIndexOf2 < enumArr2.length) {
                    return enumArr2[iIndexOf2];
                }
                throw new IllegalStateException((iIndexOf2 + " is not among valid " + str2 + " values, values size is " + enumArr2.length).toString());
        }
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        switch (this.a) {
        }
        return this.e;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        switch (this.a) {
            case 0:
                Enum value = (Enum) obj;
                Intrinsics.checkNotNullParameter(encoder, "encoder");
                Intrinsics.checkNotNullParameter(value, "value");
                Enum[] enumArr = this.c;
                int iG = C4933y.G(value, enumArr);
                if (iG != -1) {
                    encoder.w(((Number) this.d.get(iG)).intValue());
                    return;
                }
                throw new IllegalStateException((value + " is not a valid enum " + this.b + ", choices are " + enumArr).toString());
            default:
                Enum value2 = (Enum) obj;
                Intrinsics.checkNotNullParameter(encoder, "encoder");
                Intrinsics.checkNotNullParameter(value2, "value");
                Enum[] enumArr2 = this.c;
                int iG2 = C4933y.G(value2, enumArr2);
                if (iG2 != -1) {
                    encoder.E((String) this.d.get(iG2));
                    return;
                }
                String string = Arrays.toString(enumArr2);
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                StringBuilder sb = new StringBuilder();
                sb.append(value2);
                sb.append(" is not a valid enum ");
                throw new IllegalStateException(AbstractC0147y.g(sb, this.b, ", must be one of ", string).toString());
        }
    }
}
