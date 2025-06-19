package com.bumptech.glide.load.resource.gif;

import android.util.Log;
import androidx.compose.foundation.lazy.grid.m;
import com.bumptech.glide.load.ImageHeaderParser$ImageType;
import com.bumptech.glide.load.engine.v;
import com.bumptech.glide.load.j;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3567z;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class i implements j {
    public final ArrayList a;
    public final a b;
    public final m c;

    public i(ArrayList arrayList, a aVar, m mVar) {
        this.a = arrayList;
        this.b = aVar;
        this.c = mVar;
    }

    @Override // com.bumptech.glide.load.j
    public final boolean a(Object obj, com.bumptech.glide.load.h hVar) {
        return !((Boolean) hVar.c(h.b)).booleanValue() && AbstractC3567z.b(this.a, (InputStream) obj, this.c) == ImageHeaderParser$ImageType.GIF;
    }

    @Override // com.bumptech.glide.load.j
    public final v b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) throws IOException {
        byte[] byteArray;
        InputStream inputStream = (InputStream) obj;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(16384);
        try {
            byte[] bArr = new byte[16384];
            while (true) {
                int i3 = inputStream.read(bArr);
                if (i3 == -1) {
                    break;
                }
                byteArrayOutputStream.write(bArr, 0, i3);
            }
            byteArrayOutputStream.flush();
            byteArray = byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            if (Log.isLoggable("StreamGifDecoder", 5)) {
                Log.w("StreamGifDecoder", "Error reading data from stream", e);
            }
            byteArray = null;
        }
        if (byteArray == null) {
            return null;
        }
        return this.b.b(ByteBuffer.wrap(byteArray), i, i2, hVar);
    }
}
