package com.bumptech.glide.load.resource.transcode;

import android.content.Context;
import android.content.res.Resources;
import androidx.annotation.NonNull;
import com.bumptech.glide.load.engine.v;
import com.bumptech.glide.load.h;
import com.bumptech.glide.load.resource.bitmap.C1541d;
import com.bumptech.glide.util.f;

/* loaded from: classes.dex */
public class a implements b {
    public final Resources a;

    public a(@NonNull Context context) {
        this(context.getResources());
    }

    @Override // com.bumptech.glide.load.resource.transcode.b
    public final v d(v vVar, h hVar) {
        if (vVar == null) {
            return null;
        }
        return new C1541d(this.a, vVar);
    }

    public a(Resources resources) {
        f.c(resources, "Argument must not be null");
        this.a = resources;
    }
}
