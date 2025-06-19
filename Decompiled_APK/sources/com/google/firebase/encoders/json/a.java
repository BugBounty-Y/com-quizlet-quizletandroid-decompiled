package com.google.firebase.encoders.json;

import com.google.firebase.encoders.EncodingException;
import java.util.Map;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements com.google.firebase.encoders.c {
    public final /* synthetic */ int a;

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                throw new EncodingException("Couldn't find encoder for type " + obj.getClass().getCanonicalName());
            case 1:
                Map.Entry entry = (Map.Entry) obj;
                com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
                dVar.g(com.google.firebase.encoders.proto.e.g, entry.getKey());
                dVar.g(com.google.firebase.encoders.proto.e.h, entry.getValue());
                return;
            default:
                throw new EncodingException("Couldn't find encoder for type " + obj.getClass().getCanonicalName());
        }
    }
}
