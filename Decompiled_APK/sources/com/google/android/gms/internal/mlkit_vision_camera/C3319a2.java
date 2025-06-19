package com.google.android.gms.internal.mlkit_vision_camera;

import com.google.firebase.encoders.EncodingException;
import java.nio.charset.Charset;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.a2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C3319a2 implements com.google.firebase.encoders.c {
    public static final /* synthetic */ C3319a2 b = new C3319a2(0);
    public static final /* synthetic */ C3319a2 c = new C3319a2(1);
    public final /* synthetic */ int a;

    public /* synthetic */ C3319a2(int i) {
        this.a = i;
    }

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                Map.Entry entry = (Map.Entry) obj;
                com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
                Charset charset = C3414y2.f;
                dVar.g(C3414y2.g, entry.getKey());
                dVar.g(C3414y2.h, entry.getValue());
                return;
            default:
                String strValueOf = String.valueOf(obj.getClass().getCanonicalName());
                throw new EncodingException(strValueOf.length() != 0 ? "Couldn't find encoder for type ".concat(strValueOf) : new String("Couldn't find encoder for type "));
        }
    }
}
