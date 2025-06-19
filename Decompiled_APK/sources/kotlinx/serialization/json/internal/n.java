package kotlinx.serialization.json.internal;

import androidx.camera.camera2.internal.p0;
import com.google.android.gms.internal.mlkit_vision_camera.U1;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.SerializationException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.f0;
import kotlinx.serialization.json.JsonNull;

/* loaded from: classes3.dex */
public class n implements kotlinx.serialization.json.o, Encoder, kotlinx.serialization.encoding.b {
    public final ArrayList a;
    public final kotlinx.serialization.json.b b;
    public final Function1 c;
    public final kotlinx.serialization.json.i d;
    public String e;
    public String f;
    public final /* synthetic */ int g;
    public Object h;

    public n(kotlinx.serialization.json.b bVar, Function1 function1, char c) {
        this.a = new ArrayList();
        this.b = bVar;
        this.c = function1;
        this.d = bVar.a;
    }

    @Override // kotlinx.serialization.encoding.b
    public final void A(SerialDescriptor descriptor, int i, double d) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        G(K(descriptor, i), d);
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final void B(long j) {
        String tag = (String) L();
        Intrinsics.checkNotNullParameter(tag, "tag");
        M(tag, kotlinx.serialization.json.l.b(Long.valueOf(j)));
    }

    @Override // kotlinx.serialization.encoding.b
    public final void C(SerialDescriptor descriptor, int i, long j) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        String tag = K(descriptor, i);
        Intrinsics.checkNotNullParameter(tag, "tag");
        M(tag, kotlinx.serialization.json.l.b(Long.valueOf(j)));
    }

    @Override // kotlinx.serialization.encoding.b
    public final boolean D(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return this.d.a;
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final void E(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        String tag = (String) L();
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(value, "value");
        M(tag, kotlinx.serialization.json.l.c(value));
    }

    public final void F(SerialDescriptor descriptor, int i, KSerializer serializer, Object obj) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        this.a.add(K(descriptor, i));
        q(serializer, obj);
    }

    public final void G(Object obj, double d) {
        String key = (String) obj;
        Intrinsics.checkNotNullParameter(key, "tag");
        M(key, kotlinx.serialization.json.l.b(Double.valueOf(d)));
        if (this.d.h || Math.abs(d) <= Double.MAX_VALUE) {
            return;
        }
        Double value = Double.valueOf(d);
        String output = J().toString();
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(output, "output");
        throw new JsonEncodingException(k.v(value, key, output));
    }

    public final void H(Object obj, float f) {
        String key = (String) obj;
        Intrinsics.checkNotNullParameter(key, "tag");
        M(key, kotlinx.serialization.json.l.b(Float.valueOf(f)));
        if (this.d.h || Math.abs(f) <= Float.MAX_VALUE) {
            return;
        }
        Float value = Float.valueOf(f);
        String output = J().toString();
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(output, "output");
        throw new JsonEncodingException(k.v(value, key, output));
    }

    public final Encoder I(Object obj, SerialDescriptor inlineDescriptor) {
        String tag = (String) obj;
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(inlineDescriptor, "inlineDescriptor");
        if (w.a(inlineDescriptor)) {
            return new b(this, tag);
        }
        Intrinsics.checkNotNullParameter(inlineDescriptor, "<this>");
        if (inlineDescriptor.isInline() && inlineDescriptor.equals(kotlinx.serialization.json.l.a)) {
            return new b(this, tag, inlineDescriptor);
        }
        Intrinsics.checkNotNullParameter(inlineDescriptor, "inlineDescriptor");
        this.a.add(tag);
        return this;
    }

    public kotlinx.serialization.json.k J() {
        switch (this.g) {
            case 0:
                kotlinx.serialization.json.k kVar = (kotlinx.serialization.json.k) this.h;
                if (kVar != null) {
                    return kVar;
                }
                throw new IllegalArgumentException("Primitive element has not been recorded. Is call to .encodeXxx is missing in serializer?");
            case 1:
                return new kotlinx.serialization.json.v((LinkedHashMap) this.h);
            default:
                return new kotlinx.serialization.json.d((ArrayList) this.h);
        }
    }

    public final String K(SerialDescriptor descriptor, int i) {
        String childName;
        Intrinsics.checkNotNullParameter(descriptor, "<this>");
        switch (this.g) {
            case 2:
                Intrinsics.checkNotNullParameter(descriptor, "descriptor");
                childName = String.valueOf(i);
                break;
            default:
                Intrinsics.checkNotNullParameter(descriptor, "descriptor");
                Intrinsics.checkNotNullParameter(descriptor, "<this>");
                kotlinx.serialization.json.b json = this.b;
                Intrinsics.checkNotNullParameter(json, "json");
                k.q(descriptor, json);
                childName = descriptor.g(i);
                break;
        }
        Intrinsics.checkNotNullParameter(childName, "nestedName");
        String parentName = (String) CollectionsKt.V(this.a);
        if (parentName == null) {
            parentName = "";
        }
        Intrinsics.checkNotNullParameter(parentName, "parentName");
        Intrinsics.checkNotNullParameter(childName, "childName");
        return childName;
    }

    public final Object L() {
        ArrayList arrayList = this.a;
        if (arrayList.isEmpty()) {
            throw new SerializationException("No tag in stack for requested element");
        }
        return arrayList.remove(B.i(arrayList));
    }

    public void M(String key, kotlinx.serialization.json.k element) {
        switch (this.g) {
            case 0:
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(element, "element");
                if (key != "primitive") {
                    throw new IllegalArgumentException("This output can only consume primitives with 'primitive' tag");
                }
                if (((kotlinx.serialization.json.k) this.h) != null) {
                    throw new IllegalArgumentException("Primitive element was already recorded. Does call to .encodeXxx happen more than once?");
                }
                this.h = element;
                this.c.invoke(element);
                return;
            case 1:
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(element, "element");
                ((LinkedHashMap) this.h).put(key, element);
                return;
            default:
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(element, "element");
                ((ArrayList) this.h).add(Integer.parseInt(key), element);
                return;
        }
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final p0 a() {
        return this.b.b;
    }

    @Override // kotlinx.serialization.encoding.b
    public final void b(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        if (!this.a.isEmpty()) {
            L();
        }
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        this.c.invoke(J());
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final kotlinx.serialization.encoding.b c(SerialDescriptor descriptor) {
        n nVar;
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Function1 nodeConsumer = CollectionsKt.V(this.a) == null ? this.c : new com.quizlet.ui.compose.modifiers.b(this, 19);
        U1 u1E = descriptor.e();
        boolean zB = Intrinsics.b(u1E, kotlinx.serialization.descriptors.j.c);
        kotlinx.serialization.json.b json = this.b;
        if (zB || (u1E instanceof kotlinx.serialization.descriptors.d)) {
            nVar = new n(json, nodeConsumer, 2);
        } else if (Intrinsics.b(u1E, kotlinx.serialization.descriptors.j.d)) {
            SerialDescriptor serialDescriptorG = k.g(descriptor.i(0), json.b);
            U1 u1E2 = serialDescriptorG.e();
            if (!(u1E2 instanceof kotlinx.serialization.descriptors.f) && !Intrinsics.b(u1E2, kotlinx.serialization.descriptors.i.b)) {
                throw k.b(serialDescriptorG);
            }
            Intrinsics.checkNotNullParameter(json, "json");
            Intrinsics.checkNotNullParameter(nodeConsumer, "nodeConsumer");
            r rVar = new r(json, nodeConsumer, 1);
            rVar.j = true;
            nVar = rVar;
        } else {
            nVar = new n(json, nodeConsumer, 1);
        }
        String str = this.e;
        if (str != null) {
            if (nVar instanceof r) {
                r rVar2 = (r) nVar;
                rVar2.M("key", kotlinx.serialization.json.l.c(str));
                String strA = this.f;
                if (strA == null) {
                    strA = descriptor.a();
                }
                rVar2.M("value", kotlinx.serialization.json.l.c(strA));
            } else {
                String strA2 = this.f;
                if (strA2 == null) {
                    strA2 = descriptor.a();
                }
                nVar.M(str, kotlinx.serialization.json.l.c(strA2));
            }
            this.e = null;
            this.f = null;
        }
        return nVar;
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final void d() {
        String tag = (String) CollectionsKt.V(this.a);
        if (tag == null) {
            this.c.invoke(JsonNull.INSTANCE);
        } else {
            Intrinsics.checkNotNullParameter(tag, "tag");
            M(tag, JsonNull.INSTANCE);
        }
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final void e(double d) {
        G(L(), d);
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final void f(short s) {
        String tag = (String) L();
        Intrinsics.checkNotNullParameter(tag, "tag");
        M(tag, kotlinx.serialization.json.l.b(Short.valueOf(s)));
    }

    @Override // kotlinx.serialization.encoding.b
    public final void g(f0 descriptor, int i, short s) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        String tag = K(descriptor, i);
        Intrinsics.checkNotNullParameter(tag, "tag");
        M(tag, kotlinx.serialization.json.l.b(Short.valueOf(s)));
    }

    @Override // kotlinx.serialization.encoding.b
    public final void h(f0 descriptor, int i, char c) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        String tag = K(descriptor, i);
        Intrinsics.checkNotNullParameter(tag, "tag");
        M(tag, kotlinx.serialization.json.l.c(String.valueOf(c)));
    }

    @Override // kotlinx.serialization.encoding.b
    public final void i(SerialDescriptor descriptor, int i, KSerializer serializer, Object obj) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        this.a.add(K(descriptor, i));
        y(serializer, obj);
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final void j(byte b) {
        String tag = (String) L();
        Intrinsics.checkNotNullParameter(tag, "tag");
        M(tag, kotlinx.serialization.json.l.b(Byte.valueOf(b)));
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final void k(boolean z) {
        String tag = (String) L();
        Intrinsics.checkNotNullParameter(tag, "tag");
        M(tag, kotlinx.serialization.json.l.a(Boolean.valueOf(z)));
    }

    @Override // kotlinx.serialization.encoding.b
    public final void l(int i, int i2, SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        String tag = K(descriptor, i);
        Intrinsics.checkNotNullParameter(tag, "tag");
        M(tag, kotlinx.serialization.json.l.b(Integer.valueOf(i2)));
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final void m(float f) {
        H(L(), f);
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final void n(char c) {
        String tag = (String) L();
        Intrinsics.checkNotNullParameter(tag, "tag");
        M(tag, kotlinx.serialization.json.l.c(String.valueOf(c)));
    }

    @Override // kotlinx.serialization.encoding.b
    public final void o(f0 descriptor, int i, byte b) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        String tag = K(descriptor, i);
        Intrinsics.checkNotNullParameter(tag, "tag");
        M(tag, kotlinx.serialization.json.l.b(Byte.valueOf(b)));
    }

    @Override // kotlinx.serialization.encoding.b
    public final void p(SerialDescriptor descriptor, int i, boolean z) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        String tag = K(descriptor, i);
        Intrinsics.checkNotNullParameter(tag, "tag");
        M(tag, kotlinx.serialization.json.l.a(Boolean.valueOf(z)));
    }

    @Override // kotlinx.serialization.encoding.b
    public final void r(SerialDescriptor descriptor, int i, String value) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(value, "value");
        String tag = K(descriptor, i);
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(value, "value");
        M(tag, kotlinx.serialization.json.l.c(value));
    }

    @Override // kotlinx.serialization.encoding.b
    public void s(SerialDescriptor descriptor, int i, KSerializer serializer, Object obj) {
        switch (this.g) {
            case 1:
                Intrinsics.checkNotNullParameter(descriptor, "descriptor");
                Intrinsics.checkNotNullParameter(serializer, "serializer");
                if (obj != null || this.d.e) {
                    F(descriptor, i, serializer, obj);
                    break;
                }
                break;
            default:
                F(descriptor, i, serializer, obj);
                break;
        }
    }

    @Override // kotlinx.serialization.encoding.b
    public final void t(f0 descriptor, int i, float f) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        H(K(descriptor, i), f);
    }

    @Override // kotlinx.serialization.encoding.b
    public final Encoder u(f0 descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return I(K(descriptor, i), descriptor.i(i));
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final void v(SerialDescriptor enumDescriptor, int i) {
        Intrinsics.checkNotNullParameter(enumDescriptor, "enumDescriptor");
        String tag = (String) L();
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(enumDescriptor, "enumDescriptor");
        M(tag, kotlinx.serialization.json.l.c(enumDescriptor.g(i)));
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final void w(int i) {
        String tag = (String) L();
        Intrinsics.checkNotNullParameter(tag, "tag");
        M(tag, kotlinx.serialization.json.l.b(Integer.valueOf(i)));
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final Encoder x(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        if (CollectionsKt.V(this.a) == null) {
            return new n(this.b, this.c, 0).x(descriptor);
        }
        if (this.e != null) {
            this.f = descriptor.a();
        }
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return I(L(), descriptor);
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x006f  */
    @Override // kotlinx.serialization.encoding.Encoder
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void y(kotlinx.serialization.KSerializer r5, java.lang.Object r6) {
        /*
            r4 = this;
            java.lang.String r0 = "serializer"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r0)
            java.util.ArrayList r0 = r4.a
            java.lang.Object r0 = kotlin.collections.CollectionsKt.V(r0)
            kotlinx.serialization.json.b r1 = r4.b
            if (r0 != 0) goto L35
            kotlinx.serialization.descriptors.SerialDescriptor r0 = r5.getDescriptor()
            androidx.camera.camera2.internal.p0 r2 = r1.b
            kotlinx.serialization.descriptors.SerialDescriptor r0 = kotlinx.serialization.json.internal.k.g(r0, r2)
            com.google.android.gms.internal.mlkit_vision_camera.U1 r2 = r0.e()
            boolean r2 = r2 instanceof kotlinx.serialization.descriptors.f
            if (r2 != 0) goto L29
            com.google.android.gms.internal.mlkit_vision_camera.U1 r0 = r0.e()
            kotlinx.serialization.descriptors.i r2 = kotlinx.serialization.descriptors.i.b
            if (r0 != r2) goto L35
        L29:
            kotlinx.serialization.json.internal.n r0 = new kotlinx.serialization.json.internal.n
            kotlin.jvm.functions.Function1 r2 = r4.c
            r3 = 0
            r0.<init>(r1, r2, r3)
            r0.y(r5, r6)
            return
        L35:
            kotlinx.serialization.json.i r0 = r1.a
            boolean r2 = r5 instanceof kotlinx.serialization.internal.AbstractC5044b
            if (r2 == 0) goto L42
            kotlinx.serialization.json.a r0 = r0.j
            kotlinx.serialization.json.a r3 = kotlinx.serialization.json.a.a
            if (r0 == r3) goto L78
            goto L6f
        L42:
            kotlinx.serialization.json.a r0 = r0.j
            int r0 = r0.ordinal()
            if (r0 == 0) goto L78
            r3 = 1
            if (r0 == r3) goto L57
            r1 = 2
            if (r0 != r1) goto L51
            goto L78
        L51:
            kotlin.NoWhenBranchMatchedException r5 = new kotlin.NoWhenBranchMatchedException
            r5.<init>()
            throw r5
        L57:
            kotlinx.serialization.descriptors.SerialDescriptor r0 = r5.getDescriptor()
            com.google.android.gms.internal.mlkit_vision_camera.U1 r0 = r0.e()
            kotlinx.serialization.descriptors.j r3 = kotlinx.serialization.descriptors.j.b
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r0, r3)
            if (r3 != 0) goto L6f
            kotlinx.serialization.descriptors.j r3 = kotlinx.serialization.descriptors.j.e
            boolean r0 = kotlin.jvm.internal.Intrinsics.b(r0, r3)
            if (r0 == 0) goto L78
        L6f:
            kotlinx.serialization.descriptors.SerialDescriptor r0 = r5.getDescriptor()
            java.lang.String r0 = kotlinx.serialization.json.internal.k.j(r0, r1)
            goto L79
        L78:
            r0 = 0
        L79:
            if (r2 == 0) goto Lb7
            r1 = r5
            kotlinx.serialization.internal.b r1 = (kotlinx.serialization.internal.AbstractC5044b) r1
            if (r6 == 0) goto L96
            kotlinx.serialization.KSerializer r1 = com.google.android.gms.internal.mlkit_vision_camera.O1.c(r1, r4, r6)
            if (r0 == 0) goto L94
            kotlinx.serialization.json.internal.k.f(r5, r1, r0)
            kotlinx.serialization.descriptors.SerialDescriptor r5 = r1.getDescriptor()
            com.google.android.gms.internal.mlkit_vision_camera.U1 r5 = r5.e()
            kotlinx.serialization.json.internal.k.i(r5)
        L94:
            r5 = r1
            goto Lb7
        L96:
            java.lang.StringBuilder r5 = new java.lang.StringBuilder
            java.lang.String r6 = "Value for serializer "
            r5.<init>(r6)
            kotlinx.serialization.descriptors.SerialDescriptor r6 = r1.getDescriptor()
            r5.append(r6)
            java.lang.String r6 = " should always be non-null. Please report issue to the kotlinx.serialization tracker."
            r5.append(r6)
            java.lang.String r5 = r5.toString()
            java.lang.IllegalArgumentException r6 = new java.lang.IllegalArgumentException
            java.lang.String r5 = r5.toString()
            r6.<init>(r5)
            throw r6
        Lb7:
            if (r0 == 0) goto Lc5
            kotlinx.serialization.descriptors.SerialDescriptor r1 = r5.getDescriptor()
            java.lang.String r1 = r1.a()
            r4.e = r0
            r4.f = r1
        Lc5:
            r5.serialize(r4, r6)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.serialization.json.internal.n.y(kotlinx.serialization.KSerializer, java.lang.Object):void");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public n(kotlinx.serialization.json.b json, Function1 nodeConsumer, int i) {
        this(json, nodeConsumer, (char) 0);
        this.g = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(json, "json");
                Intrinsics.checkNotNullParameter(nodeConsumer, "nodeConsumer");
                this(json, nodeConsumer, (char) 0);
                this.h = new LinkedHashMap();
                break;
            case 2:
                Intrinsics.checkNotNullParameter(json, "json");
                Intrinsics.checkNotNullParameter(nodeConsumer, "nodeConsumer");
                this(json, nodeConsumer, (char) 0);
                this.h = new ArrayList();
                break;
            default:
                Intrinsics.checkNotNullParameter(json, "json");
                Intrinsics.checkNotNullParameter(nodeConsumer, "nodeConsumer");
                this.a.add("primitive");
                break;
        }
    }
}
