package kotlinx.serialization.json.internal;

import androidx.appcompat.widget.C0070a;
import androidx.appcompat.widget.C0122z;
import androidx.camera.camera2.internal.p0;
import androidx.compose.ui.node.B;
import com.google.android.gms.internal.mlkit_vision_camera.V1;
import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;

/* loaded from: classes3.dex */
public final class u extends V1 implements kotlinx.serialization.json.j {
    public final kotlinx.serialization.json.c a;
    public final y b;
    public final androidx.camera.camera2.internal.concurrent.a c;
    public final p0 d;
    public int e;
    public com.google.android.gms.ads.internal.util.client.d f;
    public final kotlinx.serialization.json.i g;
    public final j h;

    public u(kotlinx.serialization.json.c json, y mode, androidx.camera.camera2.internal.concurrent.a lexer, SerialDescriptor descriptor, com.google.android.gms.ads.internal.util.client.d dVar) {
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(mode, "mode");
        Intrinsics.checkNotNullParameter(lexer, "lexer");
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        this.a = json;
        this.b = mode;
        this.c = lexer;
        this.d = json.b;
        this.e = -1;
        this.f = dVar;
        kotlinx.serialization.json.i iVar = json.a;
        this.g = iVar;
        this.h = iVar.e ? null : new j(descriptor);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final byte A() {
        androidx.camera.camera2.internal.concurrent.a aVar = this.c;
        long jK = aVar.k();
        byte b = (byte) jK;
        if (jK == b) {
            return b;
        }
        androidx.camera.camera2.internal.concurrent.a.r(aVar, "Failed to parse byte for input '" + jK + '\'', 0, null, 6);
        throw null;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final short B() {
        androidx.camera.camera2.internal.concurrent.a aVar = this.c;
        long jK = aVar.k();
        short s = (short) jK;
        if (jK == s) {
            return s;
        }
        androidx.camera.camera2.internal.concurrent.a.r(aVar, "Failed to parse short for input '" + jK + '\'', 0, null, 6);
        throw null;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final float C() throws NumberFormatException {
        androidx.camera.camera2.internal.concurrent.a aVar = this.c;
        String strM = aVar.m();
        try {
            float f = Float.parseFloat(strM);
            if (this.a.a.h || Math.abs(f) <= Float.MAX_VALUE) {
                return f;
            }
            k.t(aVar, Float.valueOf(f));
            throw null;
        } catch (IllegalArgumentException unused) {
            androidx.camera.camera2.internal.concurrent.a.r(aVar, B.h("Failed to parse type 'float' for input '", strM, '\''), 0, null, 6);
            throw null;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final double D() throws NumberFormatException {
        androidx.camera.camera2.internal.concurrent.a aVar = this.c;
        String strM = aVar.m();
        try {
            double d = Double.parseDouble(strM);
            if (this.a.a.h || Math.abs(d) <= Double.MAX_VALUE) {
                return d;
            }
            k.t(aVar, Double.valueOf(d));
            throw null;
        } catch (IllegalArgumentException unused) {
            androidx.camera.camera2.internal.concurrent.a.r(aVar, B.h("Failed to parse type 'double' for input '", strM, '\''), 0, null, 6);
            throw null;
        }
    }

    @Override // kotlinx.serialization.encoding.Decoder, kotlinx.serialization.encoding.a
    public final p0 a() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.a
    public final void b(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        int iF = descriptor.f();
        kotlinx.serialization.json.c cVar = this.a;
        if (iF == 0 && k.n(descriptor, cVar)) {
            while (t(descriptor) != -1) {
            }
        }
        androidx.camera.camera2.internal.concurrent.a aVar = this.c;
        if (aVar.Q()) {
            kotlinx.serialization.json.i iVar = cVar.a;
            k.o(aVar, "");
            throw null;
        }
        aVar.j(this.b.b);
        C0122z c0122z = (C0122z) aVar.c;
        int i = c0122z.b;
        int[] iArr = (int[]) c0122z.d;
        if (iArr[i] == -2) {
            iArr[i] = -1;
            c0122z.b = i - 1;
        }
        int i2 = c0122z.b;
        if (i2 != -1) {
            c0122z.b = i2 - 1;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final kotlinx.serialization.encoding.a c(SerialDescriptor sd) {
        Intrinsics.checkNotNullParameter(sd, "descriptor");
        kotlinx.serialization.json.c cVar = this.a;
        y yVarS = k.s(sd, cVar);
        androidx.camera.camera2.internal.concurrent.a aVar = this.c;
        C0122z c0122z = (C0122z) aVar.c;
        Intrinsics.checkNotNullParameter(sd, "sd");
        int i = c0122z.b + 1;
        c0122z.b = i;
        Object[] objArr = (Object[]) c0122z.c;
        if (i == objArr.length) {
            int i2 = i * 2;
            Object[] objArrCopyOf = Arrays.copyOf(objArr, i2);
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
            c0122z.c = objArrCopyOf;
            int[] iArrCopyOf = Arrays.copyOf((int[]) c0122z.d, i2);
            Intrinsics.checkNotNullExpressionValue(iArrCopyOf, "copyOf(...)");
            c0122z.d = iArrCopyOf;
        }
        ((Object[]) c0122z.c)[i] = sd;
        aVar.j(yVarS.a);
        if (aVar.J() == 4) {
            androidx.camera.camera2.internal.concurrent.a.r(aVar, "Unexpected leading comma", 0, null, 6);
            throw null;
        }
        int iOrdinal = yVarS.ordinal();
        if (iOrdinal == 1 || iOrdinal == 2 || iOrdinal == 3) {
            return new u(this.a, yVarS, aVar, sd, this.f);
        }
        if (this.b == yVarS && cVar.a.e) {
            return this;
        }
        return new u(this.a, yVarS, aVar, sd, this.f);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final boolean f() {
        boolean z;
        boolean z2;
        androidx.camera.camera2.internal.concurrent.a aVar = this.c;
        int iP = aVar.P();
        String str = (String) aVar.f;
        if (iP == str.length()) {
            androidx.camera.camera2.internal.concurrent.a.r(aVar, "EOF", 0, null, 6);
            throw null;
        }
        if (str.charAt(iP) == '\"') {
            iP++;
            z = true;
        } else {
            z = false;
        }
        int iL = aVar.L(iP);
        if (iL >= str.length() || iL == -1) {
            androidx.camera.camera2.internal.concurrent.a.r(aVar, "EOF", 0, null, 6);
            throw null;
        }
        int i = iL + 1;
        int iCharAt = str.charAt(iL) | ' ';
        if (iCharAt == 102) {
            aVar.f(i, "alse");
            z2 = false;
        } else {
            if (iCharAt != 116) {
                androidx.camera.camera2.internal.concurrent.a.r(aVar, "Expected valid boolean literal prefix, but had '" + aVar.m() + '\'', 0, null, 6);
                throw null;
            }
            aVar.f(i, "rue");
            z2 = true;
        }
        if (!z) {
            return z2;
        }
        if (aVar.b == str.length()) {
            androidx.camera.camera2.internal.concurrent.a.r(aVar, "EOF", 0, null, 6);
            throw null;
        }
        if (str.charAt(aVar.b) == '\"') {
            aVar.b++;
            return z2;
        }
        androidx.camera.camera2.internal.concurrent.a.r(aVar, "Expected closing quotation mark", 0, null, 6);
        throw null;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final char h() {
        androidx.camera.camera2.internal.concurrent.a aVar = this.c;
        String strM = aVar.m();
        if (strM.length() == 1) {
            return strM.charAt(0);
        }
        androidx.camera.camera2.internal.concurrent.a.r(aVar, B.h("Expected single char, but got '", strM, '\''), 0, null, 6);
        throw null;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final int i(SerialDescriptor enumDescriptor) {
        Intrinsics.checkNotNullParameter(enumDescriptor, "enumDescriptor");
        return k.m(enumDescriptor, this.a, o(), " at path " + ((C0122z) this.c.c).q());
    }

    @Override // kotlinx.serialization.json.j
    public final kotlinx.serialization.json.k l() {
        kotlinx.serialization.json.i configuration = this.a.a;
        androidx.camera.camera2.internal.concurrent.a lexer = this.c;
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        Intrinsics.checkNotNullParameter(lexer, "lexer");
        C0070a c0070a = new C0070a();
        c0070a.c = lexer;
        c0070a.b = configuration.c;
        return c0070a.e();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final int m() {
        androidx.camera.camera2.internal.concurrent.a aVar = this.c;
        long jK = aVar.k();
        int i = (int) jK;
        if (jK == i) {
            return i;
        }
        androidx.camera.camera2.internal.concurrent.a.r(aVar, "Failed to parse int for input '" + jK + '\'', 0, null, 6);
        throw null;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final String o() {
        kotlinx.serialization.json.i iVar = this.g;
        androidx.camera.camera2.internal.concurrent.a aVar = this.c;
        return iVar.c ? aVar.n() : aVar.l();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final long p() {
        return this.c.k();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final boolean s() {
        j jVar = this.h;
        if (!(jVar != null ? jVar.b : false)) {
            androidx.camera.camera2.internal.concurrent.a aVar = this.c;
            int iL = aVar.L(aVar.P());
            String str = (String) aVar.f;
            int length = str.length() - iL;
            boolean z = false;
            if (length >= 4 && iL != -1) {
                int i = 0;
                while (true) {
                    if (i < 4) {
                        if ("null".charAt(i) != str.charAt(iL + i)) {
                            break;
                        }
                        i++;
                    } else if (length <= 4 || k.h(str.charAt(iL + 4)) != 0) {
                        aVar.b = iL + 4;
                        z = true;
                    }
                }
            }
            if (!z) {
                return true;
            }
        }
        return false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:69:0x00fd, code lost:
    
        r1 = r13.b;
        r2 = (int[]) r13.d;
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x0106, code lost:
    
        if (r2[r1] != (-2)) goto L72;
     */
    /* JADX WARN: Code restructure failed: missing block: B:71:0x0108, code lost:
    
        r2[r1] = r7;
        r13.b = r1 + r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x010d, code lost:
    
        r1 = r13.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x010f, code lost:
    
        if (r1 == r7) goto L75;
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x0111, code lost:
    
        r13.b = r1 + r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x0114, code lost:
    
        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, "key");
        r1 = kotlin.text.StringsKt.Q(r9.subSequence(0, r4.b).toString(), r3, 0, 6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x015b, code lost:
    
        throw new kotlinx.serialization.json.internal.JsonDecodingException("Encountered an unknown key '" + r3 + "' at offset " + r1 + " at path: " + r13.q() + "\nUse 'ignoreUnknownKeys = true' in 'Json {}' builder or '@JsonIgnoreUnknownKeys' annotation to ignore unknown keys.\nJSON input: " + ((java.lang.Object) kotlinx.serialization.json.internal.k.p(r1, r9)));
     */
    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlinx.serialization.encoding.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int t(kotlinx.serialization.descriptors.SerialDescriptor r22) {
        /*
            Method dump skipped, instructions count: 651
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.serialization.json.internal.u.t(kotlinx.serialization.descriptors.SerialDescriptor):int");
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x011d  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x011e  */
    @Override // kotlinx.serialization.encoding.Decoder
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object u(kotlinx.serialization.KSerializer r11) {
        /*
            Method dump skipped, instructions count: 322
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.serialization.json.internal.u.u(kotlinx.serialization.KSerializer):java.lang.Object");
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final Decoder w(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        if (w.a(descriptor)) {
            return new i(this.c, this.a);
        }
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return this;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.a
    public final Object z(SerialDescriptor descriptor, int i, KSerializer deserializer, Object obj) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        boolean z = this.b == y.e && (i & 1) == 0;
        C0122z c0122z = (C0122z) this.c.c;
        if (z) {
            int[] iArr = (int[]) c0122z.d;
            int i2 = c0122z.b;
            if (iArr[i2] == -2) {
                ((Object[]) c0122z.c)[i2] = l.a;
            }
        }
        Object objZ = super.z(descriptor, i, deserializer, obj);
        if (z) {
            int[] iArr2 = (int[]) c0122z.d;
            int i3 = c0122z.b;
            if (iArr2[i3] != -2) {
                int i4 = i3 + 1;
                c0122z.b = i4;
                Object[] objArr = (Object[]) c0122z.c;
                if (i4 == objArr.length) {
                    int i5 = i4 * 2;
                    Object[] objArrCopyOf = Arrays.copyOf(objArr, i5);
                    Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
                    c0122z.c = objArrCopyOf;
                    int[] iArrCopyOf = Arrays.copyOf((int[]) c0122z.d, i5);
                    Intrinsics.checkNotNullExpressionValue(iArrCopyOf, "copyOf(...)");
                    c0122z.d = iArrCopyOf;
                }
            }
            Object[] objArr2 = (Object[]) c0122z.c;
            int i6 = c0122z.b;
            objArr2[i6] = objZ;
            ((int[]) c0122z.d)[i6] = -2;
        }
        return objZ;
    }
}
