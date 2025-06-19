package com.google.android.gms.internal.mlkit_vision_common;

import com.google.firebase.encoders.EncodingException;
import java.nio.charset.Charset;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C3443e implements com.google.firebase.encoders.c {
    public static final /* synthetic */ C3443e b = new C3443e(0);
    public static final /* synthetic */ C3443e c = new C3443e(1);
    public final /* synthetic */ int a;

    public /* synthetic */ C3443e(int i) {
        this.a = i;
    }

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                Map.Entry entry = (Map.Entry) obj;
                com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
                Charset charset = C3449f.f;
                dVar.g(C3449f.g, entry.getKey());
                dVar.g(C3449f.h, entry.getValue());
                return;
            default:
                throw new EncodingException("Couldn't find encoder for type ".concat(String.valueOf(obj.getClass().getCanonicalName())));
        }
    }
}
