package com.bumptech.glide.load.resource.bitmap;

import android.graphics.ImageDecoder;
import java.io.InputStream;
import java.nio.ByteBuffer;

/* loaded from: classes.dex */
public final class g implements com.bumptech.glide.load.j {
    public final /* synthetic */ int a;
    public final C1540c b;

    public g(int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = new C1540c();
                break;
            default:
                this.b = new C1540c();
                break;
        }
    }

    @Override // com.bumptech.glide.load.j
    public final /* bridge */ /* synthetic */ boolean a(Object obj, com.bumptech.glide.load.h hVar) {
        switch (this.a) {
            case 0:
                break;
            default:
                break;
        }
        return true;
    }

    @Override // com.bumptech.glide.load.j
    public final com.bumptech.glide.load.engine.v b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) {
        switch (this.a) {
            case 0:
                return this.b.c(ImageDecoder.createSource((ByteBuffer) obj), i, i2, hVar);
            default:
                return this.b.c(ImageDecoder.createSource(com.bumptech.glide.util.b.b((InputStream) obj)), i, i2, hVar);
        }
    }
}
