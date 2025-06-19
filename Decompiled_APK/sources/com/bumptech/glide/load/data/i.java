package com.bumptech.glide.load.data;

import android.os.ParcelFileDescriptor;
import com.bumptech.glide.load.resource.bitmap.w;
import java.io.InputStream;
import java.util.HashMap;

/* loaded from: classes.dex */
public final class i implements g {
    public static final h c = new h(0);
    public final /* synthetic */ int a;
    public final Object b;

    public i() {
        this.a = 0;
        this.b = new HashMap();
    }

    private final void a() {
    }

    private final void b() {
    }

    public ParcelFileDescriptor c() {
        return ((ParcelFileDescriptorRewinder$InternalRewinder) this.b).rewind();
    }

    @Override // com.bumptech.glide.load.data.g
    public void f() {
        switch (this.a) {
            case 1:
            case 2:
                break;
            default:
                ((w) this.b).d();
                break;
        }
    }

    @Override // com.bumptech.glide.load.data.g
    public Object l() {
        switch (this.a) {
            case 1:
                return ((ParcelFileDescriptorRewinder$InternalRewinder) this.b).rewind();
            case 2:
                return this.b;
            default:
                w wVar = (w) this.b;
                wVar.reset();
                return wVar;
        }
    }

    public i(InputStream inputStream, androidx.compose.foundation.lazy.grid.m mVar) {
        this.a = 3;
        w wVar = new w(inputStream, mVar);
        this.b = wVar;
        wVar.mark(5242880);
    }

    public i(ParcelFileDescriptor parcelFileDescriptor) {
        this.a = 1;
        this.b = new ParcelFileDescriptorRewinder$InternalRewinder(parcelFileDescriptor);
    }

    public i(Object obj) {
        this.a = 2;
        this.b = obj;
    }
}
