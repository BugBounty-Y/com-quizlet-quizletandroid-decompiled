package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.firebase.encoders.EncodingException;
import java.util.Map;

/* loaded from: classes2.dex */
public final /* synthetic */ class M implements com.google.firebase.encoders.c {
    public final /* synthetic */ int a;

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                Map.Entry entry = (Map.Entry) obj;
                com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
                dVar.g(N.g, entry.getKey());
                dVar.g(N.h, entry.getValue());
                return;
            default:
                throw new EncodingException("Couldn't find encoder for type ".concat(String.valueOf(obj.getClass().getCanonicalName())));
        }
    }
}
