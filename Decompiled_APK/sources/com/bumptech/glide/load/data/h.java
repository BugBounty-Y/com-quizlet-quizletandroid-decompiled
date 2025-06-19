package com.bumptech.glide.load.data;

import android.os.ParcelFileDescriptor;
import java.nio.ByteBuffer;

/* loaded from: classes.dex */
public final class h implements f {
    public final /* synthetic */ int a;

    @Override // com.bumptech.glide.load.data.f
    public final g a(Object obj) {
        switch (this.a) {
            case 0:
                return new i(obj);
            case 1:
                return new i((ParcelFileDescriptor) obj);
            default:
                return new com.google.android.gms.auth.api.signin.internal.h((ByteBuffer) obj, 20);
        }
    }

    @Override // com.bumptech.glide.load.data.f
    public final Class getDataClass() {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException("Not implemented");
            case 1:
                return ParcelFileDescriptor.class;
            default:
                return ByteBuffer.class;
        }
    }
}
