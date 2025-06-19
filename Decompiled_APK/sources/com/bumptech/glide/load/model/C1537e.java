package com.bumptech.glide.load.model;

import android.content.Context;
import android.content.res.AssetFileDescriptor;
import java.io.InputStream;

/* renamed from: com.bumptech.glide.load.model.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1537e implements s {
    public final /* synthetic */ int a;
    public final Context b;

    public /* synthetic */ C1537e(Context context, int i) {
        this.a = i;
        this.b = context;
    }

    @Override // com.bumptech.glide.load.model.s
    public final r a(x xVar) {
        switch (this.a) {
            case 0:
                return new C1534b(this.b, this);
            case 1:
                return new C1534b(this.b, this);
            case 2:
                return new C1534b(this.b, this);
            case 3:
                return new C1534b(this.b, xVar.b(Integer.class, AssetFileDescriptor.class));
            default:
                return new C1534b(this.b, xVar.b(Integer.class, InputStream.class));
        }
    }
}
