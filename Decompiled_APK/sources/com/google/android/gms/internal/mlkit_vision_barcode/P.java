package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.internal.mlkit_vision_camera.C3414y2;
import com.google.android.gms.internal.mlkit_vision_common.C3449f;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C3684o;
import com.google.firebase.encoders.EncodingException;

/* loaded from: classes2.dex */
public final class P implements com.google.firebase.encoders.f {
    public final /* synthetic */ int a;
    public boolean b = false;
    public boolean c = false;
    public com.google.firebase.encoders.b d;
    public final com.google.firebase.encoders.d e;

    public /* synthetic */ P(com.google.firebase.encoders.d dVar, int i) {
        this.a = i;
        this.e = dVar;
    }

    @Override // com.google.firebase.encoders.f
    public final com.google.firebase.encoders.f e(String str) {
        switch (this.a) {
            case 0:
                if (this.b) {
                    throw new EncodingException("Cannot encode a second value in the ValueEncoderContext");
                }
                this.b = true;
                ((N) this.e).f(this.d, str, this.c);
                return this;
            case 1:
                if (this.b) {
                    throw new EncodingException("Cannot encode a second value in the ValueEncoderContext");
                }
                this.b = true;
                ((C3414y2) this.e).f(this.d, str, this.c);
                return this;
            case 2:
                if (this.b) {
                    throw new EncodingException("Cannot encode a second value in the ValueEncoderContext");
                }
                this.b = true;
                ((C3449f) this.e).f(this.d, str, this.c);
                return this;
            case 3:
                if (this.b) {
                    throw new EncodingException("Cannot encode a second value in the ValueEncoderContext");
                }
                this.b = true;
                ((C3684o) this.e).f(this.d, str, this.c);
                return this;
            default:
                if (this.b) {
                    throw new EncodingException("Cannot encode a second value in the ValueEncoderContext");
                }
                this.b = true;
                ((com.google.firebase.encoders.proto.e) this.e).h(this.d, str, this.c);
                return this;
        }
    }

    @Override // com.google.firebase.encoders.f
    public final com.google.firebase.encoders.f f(boolean z) {
        switch (this.a) {
            case 0:
                if (this.b) {
                    throw new EncodingException("Cannot encode a second value in the ValueEncoderContext");
                }
                this.b = true;
                ((N) this.e).h(this.d, z ? 1 : 0, this.c);
                return this;
            case 1:
                if (this.b) {
                    throw new EncodingException("Cannot encode a second value in the ValueEncoderContext");
                }
                this.b = true;
                ((C3414y2) this.e).h(this.d, z ? 1 : 0, this.c);
                return this;
            case 2:
                if (this.b) {
                    throw new EncodingException("Cannot encode a second value in the ValueEncoderContext");
                }
                this.b = true;
                ((C3449f) this.e).h(this.d, z ? 1 : 0, this.c);
                return this;
            case 3:
                if (this.b) {
                    throw new EncodingException("Cannot encode a second value in the ValueEncoderContext");
                }
                this.b = true;
                ((C3684o) this.e).h(this.d, z ? 1 : 0, this.c);
                return this;
            default:
                if (this.b) {
                    throw new EncodingException("Cannot encode a second value in the ValueEncoderContext");
                }
                this.b = true;
                ((com.google.firebase.encoders.proto.e) this.e).f(this.d, z ? 1 : 0, this.c);
                return this;
        }
    }
}
