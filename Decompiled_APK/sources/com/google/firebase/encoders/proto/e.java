package com.google.firebase.encoders.proto;

import com.google.android.gms.internal.mlkit_vision_barcode.I;
import com.google.android.gms.internal.mlkit_vision_barcode.P;
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
public final class e implements com.google.firebase.encoders.d {
    public static final Charset f = Charset.forName("UTF-8");
    public static final com.google.firebase.encoders.b g = new com.google.firebase.encoders.b("key", assistantMode.refactored.a.o(assistantMode.refactored.a.n(d.class, new a(1))));
    public static final com.google.firebase.encoders.b h = new com.google.firebase.encoders.b("value", assistantMode.refactored.a.o(assistantMode.refactored.a.n(d.class, new a(2))));
    public static final com.google.firebase.encoders.json.a i = new com.google.firebase.encoders.json.a(1);
    public OutputStream a;
    public final HashMap b;
    public final HashMap c;
    public final com.google.firebase.encoders.json.a d;
    public final P e = new P(this, 4);

    public e(ByteArrayOutputStream byteArrayOutputStream, HashMap map, HashMap map2, com.google.firebase.encoders.json.a aVar) {
        this.a = byteArrayOutputStream;
        this.b = map;
        this.c = map2;
        this.d = aVar;
    }

    public static int j(com.google.firebase.encoders.b bVar) {
        d dVar = (d) bVar.a(d.class);
        if (dVar != null) {
            return ((a) dVar).b;
        }
        throw new EncodingException("Field has no @Protobuf config");
    }

    @Override // com.google.firebase.encoders.d
    public final com.google.firebase.encoders.d a(com.google.firebase.encoders.b bVar, boolean z) {
        f(bVar, z ? 1 : 0, true);
        return this;
    }

    @Override // com.google.firebase.encoders.d
    public final com.google.firebase.encoders.d b(com.google.firebase.encoders.b bVar, long j) throws IOException {
        if (j == 0) {
            return this;
        }
        d dVar = (d) bVar.a(d.class);
        if (dVar == null) {
            throw new EncodingException("Field has no @Protobuf config");
        }
        k(((a) dVar).b << 3);
        l(j);
        return this;
    }

    @Override // com.google.firebase.encoders.d
    public final com.google.firebase.encoders.d c(com.google.firebase.encoders.b bVar, int i2) {
        f(bVar, i2, true);
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
        k((j(bVar) << 3) | 1);
        this.a.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putDouble(d).array());
    }

    public final void f(com.google.firebase.encoders.b bVar, int i2, boolean z) {
        if (z && i2 == 0) {
            return;
        }
        d dVar = (d) bVar.a(d.class);
        if (dVar == null) {
            throw new EncodingException("Field has no @Protobuf config");
        }
        k(((a) dVar).b << 3);
        k(i2);
    }

    @Override // com.google.firebase.encoders.d
    public final com.google.firebase.encoders.d g(com.google.firebase.encoders.b bVar, Object obj) {
        h(bVar, obj, true);
        return this;
    }

    public final void h(com.google.firebase.encoders.b bVar, Object obj, boolean z) {
        if (obj == null) {
            return;
        }
        if (obj instanceof CharSequence) {
            CharSequence charSequence = (CharSequence) obj;
            if (z && charSequence.length() == 0) {
                return;
            }
            k((j(bVar) << 3) | 2);
            byte[] bytes = charSequence.toString().getBytes(f);
            k(bytes.length);
            this.a.write(bytes);
            return;
        }
        if (obj instanceof Collection) {
            Iterator it2 = ((Collection) obj).iterator();
            while (it2.hasNext()) {
                h(bVar, it2.next(), false);
            }
            return;
        }
        if (obj instanceof Map) {
            Iterator it3 = ((Map) obj).entrySet().iterator();
            while (it3.hasNext()) {
                i(i, bVar, (Map.Entry) it3.next(), false);
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
            k((j(bVar) << 3) | 5);
            this.a.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putFloat(fFloatValue).array());
            return;
        }
        if (obj instanceof Number) {
            long jLongValue = ((Number) obj).longValue();
            if (z && jLongValue == 0) {
                return;
            }
            d dVar = (d) bVar.a(d.class);
            if (dVar == null) {
                throw new EncodingException("Field has no @Protobuf config");
            }
            k(((a) dVar).b << 3);
            l(jLongValue);
            return;
        }
        if (obj instanceof Boolean) {
            f(bVar, ((Boolean) obj).booleanValue() ? 1 : 0, z);
            return;
        }
        if (obj instanceof byte[]) {
            byte[] bArr = (byte[]) obj;
            if (z && bArr.length == 0) {
                return;
            }
            k((j(bVar) << 3) | 2);
            k(bArr.length);
            this.a.write(bArr);
            return;
        }
        com.google.firebase.encoders.c cVar = (com.google.firebase.encoders.c) this.b.get(obj.getClass());
        if (cVar != null) {
            i(cVar, bVar, obj, z);
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
        if (obj instanceof b) {
            f(bVar, ((b) obj).a(), true);
        } else if (obj instanceof Enum) {
            f(bVar, ((Enum) obj).ordinal(), true);
        } else {
            i(this.d, bVar, obj, z);
        }
    }

    public final void i(com.google.firebase.encoders.c cVar, com.google.firebase.encoders.b bVar, Object obj, boolean z) throws IOException {
        I i2 = new I(4);
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
                k((j(bVar) << 3) | 2);
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
        while ((i2 & (-128)) != 0) {
            this.a.write((i2 & 127) | 128);
            i2 >>>= 7;
        }
        this.a.write(i2 & 127);
    }

    public final void l(long j) throws IOException {
        while (((-128) & j) != 0) {
            this.a.write((((int) j) & 127) | 128);
            j >>>= 7;
        }
        this.a.write(((int) j) & 127);
    }
}
