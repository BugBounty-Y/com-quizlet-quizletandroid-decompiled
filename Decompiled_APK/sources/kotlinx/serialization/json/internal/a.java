package kotlinx.serialization.json.internal;

import androidx.camera.camera2.internal.p0;
import com.google.android.gms.internal.mlkit_vision_camera.O1;
import com.google.android.gms.internal.mlkit_vision_camera.U1;
import java.util.ArrayList;
import java.util.NoSuchElementException;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.text.D;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.SerializationException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.internal.AbstractC5044b;
import kotlinx.serialization.internal.G;
import kotlinx.serialization.internal.f0;
import kotlinx.serialization.json.JsonNull;

/* loaded from: classes3.dex */
public abstract class a implements kotlinx.serialization.json.j, Decoder, kotlinx.serialization.encoding.a {
    public final ArrayList a = new ArrayList();
    public boolean b;
    public final kotlinx.serialization.json.c c;
    public final String d;
    public final kotlinx.serialization.json.i e;

    public a(kotlinx.serialization.json.c cVar, String str) {
        this.c = cVar;
        this.d = str;
        this.e = cVar.a;
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public final byte A() {
        return I(U());
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public final short B() {
        return P(U());
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public final float C() {
        return L(U());
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public final double D() {
        return K(U());
    }

    public abstract kotlinx.serialization.json.k E(String str);

    public final kotlinx.serialization.json.k F() {
        kotlinx.serialization.json.k kVarE;
        String str = (String) CollectionsKt.V(this.a);
        return (str == null || (kVarE = E(str)) == null) ? T() : kVarE;
    }

    public final Object G(KSerializer deserializer) {
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        return u(deserializer);
    }

    public final boolean H(Object obj) {
        String tag = (String) obj;
        Intrinsics.checkNotNullParameter(tag, "tag");
        kotlinx.serialization.json.k kVarE = E(tag);
        if (!(kVarE instanceof kotlinx.serialization.json.y)) {
            throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.y.class).f() + ", but had " + K.a(kVarE.getClass()).f() + " as the serialized body of boolean at element: " + W(tag), kVarE.toString());
        }
        kotlinx.serialization.json.y yVar = (kotlinx.serialization.json.y) kVarE;
        try {
            G g = kotlinx.serialization.json.l.a;
            Intrinsics.checkNotNullParameter(yVar, "<this>");
            String strA = yVar.a();
            String[] strArr = x.a;
            Intrinsics.checkNotNullParameter(strA, "<this>");
            Boolean bool = D.l(strA, "true", true) ? Boolean.TRUE : D.l(strA, "false", true) ? Boolean.FALSE : null;
            if (bool != null) {
                return bool.booleanValue();
            }
            X(yVar, "boolean", tag);
            throw null;
        } catch (IllegalArgumentException unused) {
            X(yVar, "boolean", tag);
            throw null;
        }
    }

    public final byte I(Object obj) {
        String tag = (String) obj;
        Intrinsics.checkNotNullParameter(tag, "tag");
        kotlinx.serialization.json.k kVarE = E(tag);
        if (!(kVarE instanceof kotlinx.serialization.json.y)) {
            throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.y.class).f() + ", but had " + K.a(kVarE.getClass()).f() + " as the serialized body of byte at element: " + W(tag), kVarE.toString());
        }
        kotlinx.serialization.json.y yVar = (kotlinx.serialization.json.y) kVarE;
        try {
            long jI = kotlinx.serialization.json.l.i(yVar);
            Byte bValueOf = (-128 > jI || jI > 127) ? null : Byte.valueOf((byte) jI);
            if (bValueOf != null) {
                return bValueOf.byteValue();
            }
            X(yVar, "byte", tag);
            throw null;
        } catch (IllegalArgumentException unused) {
            X(yVar, "byte", tag);
            throw null;
        }
    }

    public final char J(Object obj) {
        String tag = (String) obj;
        Intrinsics.checkNotNullParameter(tag, "tag");
        kotlinx.serialization.json.k kVarE = E(tag);
        if (!(kVarE instanceof kotlinx.serialization.json.y)) {
            throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.y.class).f() + ", but had " + K.a(kVarE.getClass()).f() + " as the serialized body of char at element: " + W(tag), kVarE.toString());
        }
        kotlinx.serialization.json.y yVar = (kotlinx.serialization.json.y) kVarE;
        try {
            String strA = yVar.a();
            Intrinsics.checkNotNullParameter(strA, "<this>");
            int length = strA.length();
            if (length == 0) {
                throw new NoSuchElementException("Char sequence is empty.");
            }
            if (length == 1) {
                return strA.charAt(0);
            }
            throw new IllegalArgumentException("Char sequence has more than one element.");
        } catch (IllegalArgumentException unused) {
            X(yVar, "char", tag);
            throw null;
        }
    }

    public final double K(Object obj) throws NumberFormatException {
        String key = (String) obj;
        Intrinsics.checkNotNullParameter(key, "tag");
        kotlinx.serialization.json.k kVarE = E(key);
        if (!(kVarE instanceof kotlinx.serialization.json.y)) {
            throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.y.class).f() + ", but had " + K.a(kVarE.getClass()).f() + " as the serialized body of double at element: " + W(key), kVarE.toString());
        }
        kotlinx.serialization.json.y yVar = (kotlinx.serialization.json.y) kVarE;
        try {
            G g = kotlinx.serialization.json.l.a;
            Intrinsics.checkNotNullParameter(yVar, "<this>");
            double d = Double.parseDouble(yVar.a());
            if (this.c.a.h || Math.abs(d) <= Double.MAX_VALUE) {
                return d;
            }
            Double value = Double.valueOf(d);
            String output = F().toString();
            Intrinsics.checkNotNullParameter(value, "value");
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(output, "output");
            throw k.c(-1, k.v(value, key, output));
        } catch (IllegalArgumentException unused) {
            X(yVar, "double", key);
            throw null;
        }
    }

    public final float L(Object obj) throws NumberFormatException {
        String key = (String) obj;
        Intrinsics.checkNotNullParameter(key, "tag");
        kotlinx.serialization.json.k kVarE = E(key);
        if (!(kVarE instanceof kotlinx.serialization.json.y)) {
            throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.y.class).f() + ", but had " + K.a(kVarE.getClass()).f() + " as the serialized body of float at element: " + W(key), kVarE.toString());
        }
        kotlinx.serialization.json.y yVar = (kotlinx.serialization.json.y) kVarE;
        try {
            G g = kotlinx.serialization.json.l.a;
            Intrinsics.checkNotNullParameter(yVar, "<this>");
            float f = Float.parseFloat(yVar.a());
            if (this.c.a.h || Math.abs(f) <= Float.MAX_VALUE) {
                return f;
            }
            Float value = Float.valueOf(f);
            String output = F().toString();
            Intrinsics.checkNotNullParameter(value, "value");
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(output, "output");
            throw k.c(-1, k.v(value, key, output));
        } catch (IllegalArgumentException unused) {
            X(yVar, "float", key);
            throw null;
        }
    }

    public final Decoder M(Object obj, SerialDescriptor inlineDescriptor) {
        String tag = (String) obj;
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(inlineDescriptor, "inlineDescriptor");
        if (!w.a(inlineDescriptor)) {
            Intrinsics.checkNotNullParameter(inlineDescriptor, "inlineDescriptor");
            this.a.add(tag);
            return this;
        }
        kotlinx.serialization.json.k kVarE = E(tag);
        String strA = inlineDescriptor.a();
        if (kVarE instanceof kotlinx.serialization.json.y) {
            String strA2 = ((kotlinx.serialization.json.y) kVarE).a();
            kotlinx.serialization.json.c cVar = this.c;
            return new i(k.e(cVar, strA2), cVar);
        }
        throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.y.class).f() + ", but had " + K.a(kVarE.getClass()).f() + " as the serialized body of " + strA + " at element: " + W(tag), kVarE.toString());
    }

    public final int N(Object obj) {
        String tag = (String) obj;
        Intrinsics.checkNotNullParameter(tag, "tag");
        kotlinx.serialization.json.k kVarE = E(tag);
        if (!(kVarE instanceof kotlinx.serialization.json.y)) {
            throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.y.class).f() + ", but had " + K.a(kVarE.getClass()).f() + " as the serialized body of int at element: " + W(tag), kVarE.toString());
        }
        kotlinx.serialization.json.y yVar = (kotlinx.serialization.json.y) kVarE;
        try {
            long jI = kotlinx.serialization.json.l.i(yVar);
            Integer numValueOf = (-2147483648L > jI || jI > 2147483647L) ? null : Integer.valueOf((int) jI);
            if (numValueOf != null) {
                return numValueOf.intValue();
            }
            X(yVar, "int", tag);
            throw null;
        } catch (IllegalArgumentException unused) {
            X(yVar, "int", tag);
            throw null;
        }
    }

    public final long O(Object obj) {
        String tag = (String) obj;
        Intrinsics.checkNotNullParameter(tag, "tag");
        kotlinx.serialization.json.k kVarE = E(tag);
        if (kVarE instanceof kotlinx.serialization.json.y) {
            kotlinx.serialization.json.y yVar = (kotlinx.serialization.json.y) kVarE;
            try {
                return kotlinx.serialization.json.l.i(yVar);
            } catch (IllegalArgumentException unused) {
                X(yVar, "long", tag);
                throw null;
            }
        }
        throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.y.class).f() + ", but had " + K.a(kVarE.getClass()).f() + " as the serialized body of long at element: " + W(tag), kVarE.toString());
    }

    public final short P(Object obj) {
        String tag = (String) obj;
        Intrinsics.checkNotNullParameter(tag, "tag");
        kotlinx.serialization.json.k kVarE = E(tag);
        if (!(kVarE instanceof kotlinx.serialization.json.y)) {
            throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.y.class).f() + ", but had " + K.a(kVarE.getClass()).f() + " as the serialized body of short at element: " + W(tag), kVarE.toString());
        }
        kotlinx.serialization.json.y yVar = (kotlinx.serialization.json.y) kVarE;
        try {
            long jI = kotlinx.serialization.json.l.i(yVar);
            Short shValueOf = (-32768 > jI || jI > 32767) ? null : Short.valueOf((short) jI);
            if (shValueOf != null) {
                return shValueOf.shortValue();
            }
            X(yVar, "short", tag);
            throw null;
        } catch (IllegalArgumentException unused) {
            X(yVar, "short", tag);
            throw null;
        }
    }

    public final String Q(Object obj) {
        String tag = (String) obj;
        Intrinsics.checkNotNullParameter(tag, "tag");
        kotlinx.serialization.json.k kVarE = E(tag);
        if (!(kVarE instanceof kotlinx.serialization.json.y)) {
            throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.y.class).f() + ", but had " + K.a(kVarE.getClass()).f() + " as the serialized body of string at element: " + W(tag), kVarE.toString());
        }
        kotlinx.serialization.json.y yVar = (kotlinx.serialization.json.y) kVarE;
        if (!(yVar instanceof kotlinx.serialization.json.r)) {
            StringBuilder sbY = android.support.v4.media.session.a.y("Expected string value for a non-null key '", tag, "', got null literal instead at element: ");
            sbY.append(W(tag));
            throw k.d(-1, sbY.toString(), F().toString());
        }
        kotlinx.serialization.json.r rVar = (kotlinx.serialization.json.r) yVar;
        if (rVar.a || this.c.a.c) {
            return rVar.c;
        }
        StringBuilder sbY2 = android.support.v4.media.session.a.y("String literal for key '", tag, "' should be quoted at element: ");
        sbY2.append(W(tag));
        sbY2.append(".\nUse 'isLenient = true' in 'Json {}' builder to accept non-compliant JSON.");
        throw k.d(-1, sbY2.toString(), F().toString());
    }

    public String R(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return descriptor.g(i);
    }

    public final String S(SerialDescriptor serialDescriptor, int i) {
        Intrinsics.checkNotNullParameter(serialDescriptor, "<this>");
        String childName = R(serialDescriptor, i);
        Intrinsics.checkNotNullParameter(childName, "nestedName");
        String parentName = (String) CollectionsKt.V(this.a);
        if (parentName == null) {
            parentName = "";
        }
        Intrinsics.checkNotNullParameter(parentName, "parentName");
        Intrinsics.checkNotNullParameter(childName, "childName");
        return childName;
    }

    public abstract kotlinx.serialization.json.k T();

    public final Object U() {
        ArrayList arrayList = this.a;
        Object objRemove = arrayList.remove(B.i(arrayList));
        this.b = true;
        return objRemove;
    }

    public final String V() {
        ArrayList arrayList = this.a;
        return arrayList.isEmpty() ? "$" : CollectionsKt.S(arrayList, ".", "$.", null, null, 60);
    }

    public final String W(String currentTag) {
        Intrinsics.checkNotNullParameter(currentTag, "currentTag");
        return V() + '.' + currentTag;
    }

    public final void X(kotlinx.serialization.json.y yVar, String str, String str2) {
        throw k.d(-1, "Failed to parse literal '" + yVar + "' as " + (D.r(str, "i", false) ? "an " : "a ").concat(str) + " value at element: " + W(str2), F().toString());
    }

    @Override // kotlinx.serialization.encoding.Decoder, kotlinx.serialization.encoding.a
    public final p0 a() {
        return this.c.b;
    }

    @Override // kotlinx.serialization.encoding.a
    public void b(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public kotlinx.serialization.encoding.a c(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        kotlinx.serialization.json.k kVarF = F();
        U1 u1E = descriptor.e();
        boolean zB = Intrinsics.b(u1E, kotlinx.serialization.descriptors.j.c);
        kotlinx.serialization.json.c cVar = this.c;
        if (zB || (u1E instanceof kotlinx.serialization.descriptors.d)) {
            String strA = descriptor.a();
            if (kVarF instanceof kotlinx.serialization.json.d) {
                return new p(cVar, (kotlinx.serialization.json.d) kVarF);
            }
            throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.d.class).f() + ", but had " + K.a(kVarF.getClass()).f() + " as the serialized body of " + strA + " at element: " + V(), kVarF.toString());
        }
        if (!Intrinsics.b(u1E, kotlinx.serialization.descriptors.j.d)) {
            String strA2 = descriptor.a();
            if (kVarF instanceof kotlinx.serialization.json.v) {
                return new o(cVar, (kotlinx.serialization.json.v) kVarF, this.d, 8);
            }
            throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.v.class).f() + ", but had " + K.a(kVarF.getClass()).f() + " as the serialized body of " + strA2 + " at element: " + V(), kVarF.toString());
        }
        SerialDescriptor serialDescriptorG = k.g(descriptor.i(0), cVar.b);
        U1 u1E2 = serialDescriptorG.e();
        if (!(u1E2 instanceof kotlinx.serialization.descriptors.f) && !Intrinsics.b(u1E2, kotlinx.serialization.descriptors.i.b)) {
            throw k.b(serialDescriptorG);
        }
        String strA3 = descriptor.a();
        if (kVarF instanceof kotlinx.serialization.json.v) {
            return new q(cVar, (kotlinx.serialization.json.v) kVarF);
        }
        throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.v.class).f() + ", but had " + K.a(kVarF.getClass()).f() + " as the serialized body of " + strA3 + " at element: " + V(), kVarF.toString());
    }

    @Override // kotlinx.serialization.encoding.a
    public final short d(f0 descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return P(S(descriptor, i));
    }

    @Override // kotlinx.serialization.encoding.a
    public final float e(f0 descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return L(S(descriptor, i));
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public final boolean f() {
        return H(U());
    }

    @Override // kotlinx.serialization.encoding.a
    public final char g(f0 descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return J(S(descriptor, i));
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public final char h() {
        return J(U());
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public final int i(SerialDescriptor enumDescriptor) {
        Intrinsics.checkNotNullParameter(enumDescriptor, "enumDescriptor");
        String tag = (String) U();
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(enumDescriptor, "enumDescriptor");
        kotlinx.serialization.json.k kVarE = E(tag);
        String strA = enumDescriptor.a();
        if (kVarE instanceof kotlinx.serialization.json.y) {
            return k.m(enumDescriptor, this.c, ((kotlinx.serialization.json.y) kVarE).a(), "");
        }
        throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.y.class).f() + ", but had " + K.a(kVarE.getClass()).f() + " as the serialized body of " + strA + " at element: " + W(tag), kVarE.toString());
    }

    @Override // kotlinx.serialization.encoding.a
    public final long j(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return O(S(descriptor, i));
    }

    @Override // kotlinx.serialization.encoding.a
    public final byte k(f0 descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return I(S(descriptor, i));
    }

    @Override // kotlinx.serialization.json.j
    public final kotlinx.serialization.json.k l() {
        return F();
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public final int m() {
        return N(U());
    }

    @Override // kotlinx.serialization.encoding.a
    public final int n(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return N(S(descriptor, i));
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public final String o() {
        return Q(U());
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public final long p() {
        return O(U());
    }

    @Override // kotlinx.serialization.encoding.a
    public final boolean q(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return H(S(descriptor, i));
    }

    @Override // kotlinx.serialization.encoding.a
    public final String r(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return Q(S(descriptor, i));
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public boolean s() {
        return !(F() instanceof JsonNull);
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public final Object u(KSerializer deserializer) {
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        if (!(deserializer instanceof AbstractC5044b)) {
            return deserializer.deserialize(this);
        }
        kotlinx.serialization.json.c cVar = this.c;
        kotlinx.serialization.json.i iVar = cVar.a;
        AbstractC5044b abstractC5044b = (AbstractC5044b) deserializer;
        String strJ = k.j(abstractC5044b.getDescriptor(), cVar);
        kotlinx.serialization.json.k kVarF = F();
        String strA = abstractC5044b.getDescriptor().a();
        if (kVarF instanceof kotlinx.serialization.json.v) {
            kotlinx.serialization.json.v vVar = (kotlinx.serialization.json.v) kVarF;
            kotlinx.serialization.json.k kVar = (kotlinx.serialization.json.k) vVar.get(strJ);
            try {
                return k.r(cVar, strJ, vVar, O1.b((AbstractC5044b) deserializer, this, kVar != null ? kotlinx.serialization.json.l.e(kotlinx.serialization.json.l.h(kVar)) : null));
            } catch (SerializationException e) {
                String message = e.getMessage();
                Intrinsics.d(message);
                throw k.d(-1, message, vVar.toString());
            }
        }
        throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.v.class).f() + ", but had " + K.a(kVarF.getClass()).f() + " as the serialized body of " + strA + " at element: " + V(), kVarF.toString());
    }

    @Override // kotlinx.serialization.encoding.a
    public final Object v(SerialDescriptor descriptor, int i, KSerializer deserializer, Object obj) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        this.a.add(S(descriptor, i));
        Object objG = (deserializer.getDescriptor().c() || s()) ? G(deserializer) : null;
        if (!this.b) {
            U();
        }
        this.b = false;
        return objG;
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public final Decoder w(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        if (CollectionsKt.V(this.a) != null) {
            Intrinsics.checkNotNullParameter(descriptor, "descriptor");
            return M(U(), descriptor);
        }
        return new m(this.c, T(), this.d).w(descriptor);
    }

    @Override // kotlinx.serialization.encoding.a
    public final Decoder x(f0 descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return M(S(descriptor, i), descriptor.i(i));
    }

    @Override // kotlinx.serialization.encoding.a
    public final double y(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return K(S(descriptor, i));
    }

    @Override // kotlinx.serialization.encoding.a
    public final Object z(SerialDescriptor descriptor, int i, KSerializer deserializer, Object obj) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        this.a.add(S(descriptor, i));
        Object objG = G(deserializer);
        if (!this.b) {
            U();
        }
        this.b = false;
        return objG;
    }
}
