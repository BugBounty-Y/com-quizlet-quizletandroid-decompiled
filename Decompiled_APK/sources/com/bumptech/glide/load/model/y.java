package com.bumptech.glide.load.model;

import android.content.res.AssetFileDescriptor;
import android.content.res.Resources;
import android.net.Uri;
import java.io.InputStream;

/* loaded from: classes.dex */
public final class y implements s {
    public final /* synthetic */ int a;
    public final Resources b;

    public /* synthetic */ y(Resources resources, int i) {
        this.a = i;
        this.b = resources;
    }

    @Override // com.bumptech.glide.load.model.s
    public final r a(x xVar) {
        switch (this.a) {
            case 0:
                return new C1534b(this.b, xVar.b(Uri.class, AssetFileDescriptor.class));
            case 1:
                return new C1534b(this.b, xVar.b(Uri.class, InputStream.class));
            default:
                return new C1534b(this.b, B.b);
        }
    }
}
