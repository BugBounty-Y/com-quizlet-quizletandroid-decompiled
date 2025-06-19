package com.bumptech.glide.load.model;

import android.content.res.AssetFileDescriptor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import java.io.InputStream;

/* loaded from: classes.dex */
public final class A implements s {
    public static final A b = new A(0);
    public final /* synthetic */ int a;

    public /* synthetic */ A(int i) {
        this.a = i;
    }

    @Override // com.bumptech.glide.load.model.s
    public final r a(x xVar) {
        switch (this.a) {
            case 0:
                return B.b;
            case 1:
                return new com.bumptech.glide.integration.okhttp3.c(new C1535c(0), 1);
            case 2:
                return new com.bumptech.glide.integration.okhttp3.c(new C1535c(1), 1);
            case 3:
                return new B(1);
            case 4:
                return new z(xVar.b(Uri.class, AssetFileDescriptor.class), 0);
            case 5:
                return new z(xVar.b(Uri.class, ParcelFileDescriptor.class), 0);
            case 6:
                return new z(xVar.b(Uri.class, InputStream.class), 0);
            default:
                return new E(xVar.b(h.class, InputStream.class));
        }
    }
}
