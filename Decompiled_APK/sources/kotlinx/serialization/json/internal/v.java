package kotlinx.serialization.json.internal;

import androidx.appcompat.app.K;
import androidx.camera.camera2.internal.p0;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public final class v extends W1 implements kotlinx.serialization.json.o {
    public final K a;
    public final kotlinx.serialization.json.c b;
    public final y c;
    public final kotlinx.serialization.json.o[] d;
    public final p0 e;
    public final kotlinx.serialization.json.i f;
    public boolean g;
    public String h;
    public String i;

    public v(K composer, kotlinx.serialization.json.c json, y mode, kotlinx.serialization.json.o[] oVarArr) {
        Intrinsics.checkNotNullParameter(composer, "composer");
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(mode, "mode");
        this.a = composer;
        this.b = json;
        this.c = mode;
        this.d = oVarArr;
        this.e = json.b;
        this.f = json.a;
        int iOrdinal = mode.ordinal();
        if (oVarArr != null) {
            kotlinx.serialization.json.o oVar = oVarArr[iOrdinal];
            if (oVar == null && oVar == this) {
                return;
            }
            oVarArr[iOrdinal] = this;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final void B(long j) {
        if (this.g) {
            E(String.valueOf(j));
        } else {
            this.a.B(j);
        }
    }

    @Override // kotlinx.serialization.encoding.b
    public final boolean D(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return this.f.a;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final void E(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.a.E(value);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1
    public final void L(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        int iOrdinal = this.c.ordinal();
        boolean z = true;
        K k = this.a;
        if (iOrdinal == 1) {
            if (!k.a) {
                k.x(',');
            }
            k.u();
            return;
        }
        if (iOrdinal == 2) {
            if (k.a) {
                this.g = true;
                k.u();
                return;
            }
            if (i % 2 == 0) {
                k.x(',');
                k.u();
            } else {
                k.x(':');
                k.I();
                z = false;
            }
            this.g = z;
            return;
        }
        if (iOrdinal == 3) {
            if (i == 0) {
                this.g = true;
            }
            if (i == 1) {
                k.x(',');
                k.I();
                this.g = false;
                return;
            }
            return;
        }
        if (!k.a) {
            k.x(',');
        }
        k.u();
        Intrinsics.checkNotNullParameter(descriptor, "<this>");
        kotlinx.serialization.json.c json = this.b;
        Intrinsics.checkNotNullParameter(json, "json");
        k.q(descriptor, json);
        E(descriptor.g(i));
        k.x(':');
        k.I();
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final p0 a() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.b
    public final void b(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        y yVar = this.c;
        K k = this.a;
        k.K();
        k.v();
        k.x(yVar.b);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final kotlinx.serialization.encoding.b c(SerialDescriptor descriptor) {
        kotlinx.serialization.json.o oVar;
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        kotlinx.serialization.json.c cVar = this.b;
        y yVarS = k.s(descriptor, cVar);
        char c = yVarS.a;
        K k = this.a;
        k.x(c);
        k.s();
        String str = this.h;
        if (str != null) {
            String strA = this.i;
            if (strA == null) {
                strA = descriptor.a();
            }
            k.u();
            E(str);
            k.x(':');
            k.I();
            E(strA);
            this.h = null;
            this.i = null;
        }
        if (this.c == yVarS) {
            return this;
        }
        kotlinx.serialization.json.o[] oVarArr = this.d;
        return (oVarArr == null || (oVar = oVarArr[yVarS.ordinal()]) == null) ? new v(k, cVar, yVarS, oVarArr) : oVar;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final void d() {
        this.a.C("null");
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final void e(double d) {
        boolean z = this.g;
        K k = this.a;
        if (z) {
            E(String.valueOf(d));
        } else {
            k.getClass();
            ((com.android.billingclient.api.s) k.b).n(String.valueOf(d));
        }
        if (!this.f.h && Math.abs(d) > Double.MAX_VALUE) {
            throw k.a(Double.valueOf(d), ((com.android.billingclient.api.s) k.b).toString());
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final void f(short s) {
        if (this.g) {
            E(String.valueOf((int) s));
        } else {
            this.a.D(s);
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final void j(byte b) {
        if (this.g) {
            E(String.valueOf((int) b));
        } else {
            this.a.w(b);
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final void k(boolean z) {
        if (this.g) {
            E(String.valueOf(z));
            return;
        }
        K k = this.a;
        k.getClass();
        ((com.android.billingclient.api.s) k.b).n(String.valueOf(z));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final void m(float f) {
        boolean z = this.g;
        K k = this.a;
        if (z) {
            E(String.valueOf(f));
        } else {
            k.getClass();
            ((com.android.billingclient.api.s) k.b).n(String.valueOf(f));
        }
        if (!this.f.h && Math.abs(f) > Float.MAX_VALUE) {
            throw k.a(Float.valueOf(f), ((com.android.billingclient.api.s) k.b).toString());
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final void n(char c) {
        E(String.valueOf(c));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.b
    public final void s(SerialDescriptor descriptor, int i, KSerializer serializer, Object obj) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        if (obj != null || this.f.e) {
            super.s(descriptor, i, serializer, obj);
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final void v(SerialDescriptor enumDescriptor, int i) {
        Intrinsics.checkNotNullParameter(enumDescriptor, "enumDescriptor");
        E(enumDescriptor.g(i));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final void w(int i) {
        if (this.g) {
            E(String.valueOf(i));
        } else {
            this.a.A(i);
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final Encoder x(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        boolean zA = w.a(descriptor);
        y yVar = this.c;
        kotlinx.serialization.json.c cVar = this.b;
        K fVar = this.a;
        if (zA) {
            if (!(fVar instanceof g)) {
                fVar = new g((com.android.billingclient.api.s) fVar.b, this.g);
            }
            return new v(fVar, cVar, yVar, null);
        }
        Intrinsics.checkNotNullParameter(descriptor, "<this>");
        if (descriptor.isInline() && descriptor.equals(kotlinx.serialization.json.l.a)) {
            if (!(fVar instanceof f)) {
                fVar = new f((com.android.billingclient.api.s) fVar.b, this.g);
            }
            return new v(fVar, cVar, yVar, null);
        }
        if (this.h != null) {
            this.i = descriptor.a();
            return this;
        }
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return this;
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x0041  */
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
            kotlinx.serialization.json.c r0 = r4.b
            kotlinx.serialization.json.i r1 = r0.a
            boolean r2 = r5 instanceof kotlinx.serialization.internal.AbstractC5044b
            if (r2 == 0) goto L14
            kotlinx.serialization.json.a r1 = r1.j
            kotlinx.serialization.json.a r3 = kotlinx.serialization.json.a.a
            if (r1 == r3) goto L4a
            goto L41
        L14:
            kotlinx.serialization.json.a r1 = r1.j
            int r1 = r1.ordinal()
            if (r1 == 0) goto L4a
            r3 = 1
            if (r1 == r3) goto L29
            r0 = 2
            if (r1 != r0) goto L23
            goto L4a
        L23:
            kotlin.NoWhenBranchMatchedException r5 = new kotlin.NoWhenBranchMatchedException
            r5.<init>()
            throw r5
        L29:
            kotlinx.serialization.descriptors.SerialDescriptor r1 = r5.getDescriptor()
            com.google.android.gms.internal.mlkit_vision_camera.U1 r1 = r1.e()
            kotlinx.serialization.descriptors.j r3 = kotlinx.serialization.descriptors.j.b
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r1, r3)
            if (r3 != 0) goto L41
            kotlinx.serialization.descriptors.j r3 = kotlinx.serialization.descriptors.j.e
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r1, r3)
            if (r1 == 0) goto L4a
        L41:
            kotlinx.serialization.descriptors.SerialDescriptor r1 = r5.getDescriptor()
            java.lang.String r0 = kotlinx.serialization.json.internal.k.j(r1, r0)
            goto L4b
        L4a:
            r0 = 0
        L4b:
            if (r2 == 0) goto L89
            r1 = r5
            kotlinx.serialization.internal.b r1 = (kotlinx.serialization.internal.AbstractC5044b) r1
            if (r6 == 0) goto L68
            kotlinx.serialization.KSerializer r1 = com.google.android.gms.internal.mlkit_vision_camera.O1.c(r1, r4, r6)
            if (r0 == 0) goto L66
            kotlinx.serialization.json.internal.k.f(r5, r1, r0)
            kotlinx.serialization.descriptors.SerialDescriptor r5 = r1.getDescriptor()
            com.google.android.gms.internal.mlkit_vision_camera.U1 r5 = r5.e()
            kotlinx.serialization.json.internal.k.i(r5)
        L66:
            r5 = r1
            goto L89
        L68:
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
        L89:
            if (r0 == 0) goto L97
            kotlinx.serialization.descriptors.SerialDescriptor r1 = r5.getDescriptor()
            java.lang.String r1 = r1.a()
            r4.h = r0
            r4.i = r1
        L97:
            r5.serialize(r4, r6)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.serialization.json.internal.v.y(kotlinx.serialization.KSerializer, java.lang.Object):void");
    }
}
