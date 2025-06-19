package com.bumptech.glide.load.resource.drawable;

import android.graphics.ImageDecoder;
import android.os.Build;
import androidx.compose.foundation.lazy.grid.m;
import androidx.compose.foundation.text.input.internal.u;
import com.bumptech.glide.load.ImageHeaderParser$ImageType;
import com.bumptech.glide.load.engine.v;
import com.bumptech.glide.load.h;
import com.bumptech.glide.load.j;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3567z;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class a implements j {
    public final /* synthetic */ int a;
    public final u b;

    public /* synthetic */ a(u uVar, int i) {
        this.a = i;
        this.b = uVar;
    }

    @Override // com.bumptech.glide.load.j
    public final boolean a(Object obj, h hVar) throws IOException {
        switch (this.a) {
            case 0:
                ImageHeaderParser$ImageType imageHeaderParser$ImageTypeC = AbstractC3567z.c((ArrayList) this.b.b, (ByteBuffer) obj);
                if (imageHeaderParser$ImageTypeC == ImageHeaderParser$ImageType.ANIMATED_WEBP || (Build.VERSION.SDK_INT >= 31 && imageHeaderParser$ImageTypeC == ImageHeaderParser$ImageType.ANIMATED_AVIF)) {
                }
                break;
            default:
                u uVar = this.b;
                ImageHeaderParser$ImageType imageHeaderParser$ImageTypeB = AbstractC3567z.b((ArrayList) uVar.b, (InputStream) obj, (m) uVar.c);
                if (imageHeaderParser$ImageTypeB == ImageHeaderParser$ImageType.ANIMATED_WEBP || (Build.VERSION.SDK_INT >= 31 && imageHeaderParser$ImageTypeB == ImageHeaderParser$ImageType.ANIMATED_AVIF)) {
                }
                break;
        }
        return true;
    }

    @Override // com.bumptech.glide.load.j
    public final v b(Object obj, int i, int i2, h hVar) {
        switch (this.a) {
            case 0:
                return u.e(ImageDecoder.createSource((ByteBuffer) obj), i, i2, hVar);
            default:
                return u.e(ImageDecoder.createSource(com.bumptech.glide.util.b.b((InputStream) obj)), i, i2, hVar);
        }
    }
}
