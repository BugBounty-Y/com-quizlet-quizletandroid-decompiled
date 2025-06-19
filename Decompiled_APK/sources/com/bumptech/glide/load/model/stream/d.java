package com.bumptech.glide.load.model.stream;

import android.content.Context;
import android.net.Uri;
import com.bumptech.glide.load.model.r;
import com.bumptech.glide.load.model.s;
import com.bumptech.glide.load.model.x;
import java.io.File;

/* loaded from: classes.dex */
public abstract class d implements s {
    public final Context a;
    public final Class b;

    public d(Context context, Class cls) {
        this.a = context;
        this.b = cls;
    }

    @Override // com.bumptech.glide.load.model.s
    public final r a(x xVar) {
        Class cls = this.b;
        return new i(this.a, xVar.b(File.class, cls), xVar.b(Uri.class, cls), cls);
    }
}
