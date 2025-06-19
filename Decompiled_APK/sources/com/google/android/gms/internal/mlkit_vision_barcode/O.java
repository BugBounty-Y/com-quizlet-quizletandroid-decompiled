package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.firebase.encoders.EncodingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class O implements com.google.firebase.encoders.config.a {
    public static final M d = new M(1);
    public Object a;
    public Serializable b;
    public Object c;

    public byte[] a(C3306y5 c3306y5) {
        N n;
        com.google.firebase.encoders.c cVar;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            HashMap map = (HashMap) this.a;
            n = new N(byteArrayOutputStream, map, (HashMap) this.b, (M) this.c);
            cVar = (com.google.firebase.encoders.c) map.get(C3306y5.class);
        } catch (IOException unused) {
        }
        if (cVar == null) {
            throw new EncodingException("No encoder for ".concat(String.valueOf(C3306y5.class)));
        }
        cVar.a(c3306y5, n);
        return byteArrayOutputStream.toByteArray();
    }

    @Override // com.google.firebase.encoders.config.a
    public /* bridge */ /* synthetic */ com.google.firebase.encoders.config.a g(Class cls, com.google.firebase.encoders.c cVar) {
        ((HashMap) this.a).put(cls, cVar);
        ((HashMap) this.b).remove(cls);
        return this;
    }
}
