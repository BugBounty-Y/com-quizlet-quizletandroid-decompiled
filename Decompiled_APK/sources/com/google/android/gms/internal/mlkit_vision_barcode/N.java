package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import com.google.firebase.encoders.EncodingException;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes2.dex */
public final class N implements com.google.firebase.encoders.d {
    public static final Charset f = Charset.forName("UTF-8");
    public static final com.google.firebase.encoders.b g = new com.google.firebase.encoders.b("key", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(1))));
    public static final com.google.firebase.encoders.b h = new com.google.firebase.encoders.b("value", assistantMode.refactored.a.o(AbstractC1642h.n(L.class, new H(2))));
    public static final M i = new M(0);
    public OutputStream a;
    public final HashMap b;
    public final HashMap c;
    public final M d;
    public final P e = new P(this, 0);

    public N(ByteArrayOutputStream byteArrayOutputStream, HashMap map, HashMap map2, M m) {
        this.a = byteArrayOutputStream;
        this.b = map;
        this.c = map2;
        this.d = m;
    }

    public static int i(com.google.firebase.encoders.b bVar) {
        L l = (L) bVar.a(L.class);
        if (l != null) {
            return ((H) l).b;
        }
        throw new EncodingException("Field has no @Protobuf config");
    }

    @Override // com.google.firebase.encoders.d
    public final /* synthetic */ com.google.firebase.encoders.d a(com.google.firebase.encoders.b bVar, boolean z) {
        h(bVar, z ? 1 : 0, true);
        return this;
    }

    @Override // com.google.firebase.encoders.d
    public final com.google.firebase.encoders.d b(com.google.firebase.encoders.b bVar, long j) throws IOException {
        if (j == 0) {
            return this;
        }
        L l = (L) bVar.a(L.class);
        if (l == null) {
            throw new EncodingException("Field has no @Protobuf config");
        }
        k(((H) l).b << 3);
        l(j);
        return this;
    }

    @Override // com.google.firebase.encoders.d
    public final /* synthetic */ com.google.firebase.encoders.d c(com.google.firebase.encoders.b bVar, int i2) {
        h(bVar, i2, true);
        return this;
    }

    @Override // com.google.firebase.encoders.d
    public final com.google.firebase.encoders.d d(com.google.firebase.encoders.b bVar, double d) throws IOException {
        e(bVar, d, true);
        return this;
    }

    public final void e(com.google.firebase.encoders.b bVar, double d, boolean z) throws IOException {
        if (z && d == 0.0d) {
            return;
        }
        k((i(bVar) << 3) | 1);
        this.a.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putDouble(d).array());
    }

    public final void f(com.google.firebase.encoders.b bVar, Object obj, boolean z) {
        if (obj == null) {
            return;
        }
        if (obj instanceof CharSequence) {
            CharSequence charSequence = (CharSequence) obj;
            if (z && charSequence.length() == 0) {
                return;
            }
            k((i(bVar) << 3) | 2);
            byte[] bytes = charSequence.toString().getBytes(f);
            k(bytes.length);
            this.a.write(bytes);
            return;
        }
        if (obj instanceof Collection) {
            Iterator it2 = ((Collection) obj).iterator();
            while (it2.hasNext()) {
                f(bVar, it2.next(), false);
            }
            return;
        }
        if (obj instanceof Map) {
            Iterator it3 = ((Map) obj).entrySet().iterator();
            while (it3.hasNext()) {
                j(i, bVar, (Map.Entry) it3.next(), false);
            }
            return;
        }
        if (obj instanceof Double) {
            e(bVar, ((Double) obj).doubleValue(), z);
            return;
        }
        if (obj instanceof Float) {
            float fFloatValue = ((Float) obj).floatValue();
            if (z && fFloatValue == DefinitionKt.NO_Float_VALUE) {
                return;
            }
            k((i(bVar) << 3) | 5);
            this.a.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putFloat(fFloatValue).array());
            return;
        }
        if (obj instanceof Number) {
            long jLongValue = ((Number) obj).longValue();
            if (z && jLongValue == 0) {
                return;
            }
            L l = (L) bVar.a(L.class);
            if (l == null) {
                throw new EncodingException("Field has no @Protobuf config");
            }
            k(((H) l).b << 3);
            l(jLongValue);
            return;
        }
        if (obj instanceof Boolean) {
            h(bVar, ((Boolean) obj).booleanValue() ? 1 : 0, z);
            return;
        }
        if (obj instanceof byte[]) {
            byte[] bArr = (byte[]) obj;
            if (z && bArr.length == 0) {
                return;
            }
            k((i(bVar) << 3) | 2);
            k(bArr.length);
            this.a.write(bArr);
            return;
        }
        com.google.firebase.encoders.c cVar = (com.google.firebase.encoders.c) this.b.get(obj.getClass());
        if (cVar != null) {
            j(cVar, bVar, obj, z);
            return;
        }
        com.google.firebase.encoders.e eVar = (com.google.firebase.encoders.e) this.c.get(obj.getClass());
        if (eVar != null) {
            P p = this.e;
            p.b = false;
            p.d = bVar;
            p.c = z;
            eVar.a(obj, p);
            return;
        }
        if (obj instanceof J) {
            h(bVar, ((J) obj).zza(), true);
        } else if (obj instanceof Enum) {
            h(bVar, ((Enum) obj).ordinal(), true);
        } else {
            j(this.d, bVar, obj, z);
        }
    }

    @Override // com.google.firebase.encoders.d
    public final com.google.firebase.encoders.d g(com.google.firebase.encoders.b bVar, Object obj) {
        f(bVar, obj, true);
        return this;
    }

    public final void h(com.google.firebase.encoders.b bVar, int i2, boolean z) {
        if (z && i2 == 0) {
            return;
        }
        L l = (L) bVar.a(L.class);
        if (l == null) {
            throw new EncodingException("Field has no @Protobuf config");
        }
        k(((H) l).b << 3);
        k(i2);
    }

    public final void j(com.google.firebase.encoders.c cVar, com.google.firebase.encoders.b bVar, Object obj, boolean z) throws IOException {
        I i2 = new I(0);
        i2.b = 0L;
        try {
            OutputStream outputStream = this.a;
            this.a = i2;
            try {
                cVar.a(obj, this);
                this.a = outputStream;
                long j = i2.b;
                i2.close();
                if (z && j == 0) {
                    return;
                }
                k((i(bVar) << 3) | 2);
                l(j);
                cVar.a(obj, this);
            } catch (Throwable th) {
                this.a = outputStream;
                throw th;
            }
        } catch (Throwable th2) {
            try {
                i2.close();
            } catch (Throwable th3) {
                th2.addSuppressed(th3);
            }
            throw th2;
        }
    }

    public final void k(int i2) throws IOException {
        while (true) {
            int i3 = i2 & 127;
            if ((i2 & (-128)) == 0) {
                this.a.write(i3);
                return;
            } else {
                this.a.write(i3 | 128);
                i2 >>>= 7;
            }
        }
    }

    public final void l(long j) throws IOException {
        while (true) {
            int i2 = ((int) j) & 127;
            if (((-128) & j) == 0) {
                this.a.write(i2);
                return;
            } else {
                this.a.write(i2 | 128);
                j >>>= 7;
            }
        }
    }
}
