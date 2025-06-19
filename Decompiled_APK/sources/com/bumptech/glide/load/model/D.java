package com.bumptech.glide.load.model;

import android.net.Uri;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/* loaded from: classes.dex */
public final class D implements r {
    public static final Set b = Collections.unmodifiableSet(new HashSet(Arrays.asList("file", "content", "android.resource")));
    public final Object a;

    public D(C c) {
        this.a = c;
    }

    @Override // com.bumptech.glide.load.model.r
    public final boolean a(Object obj) {
        return b.contains(((Uri) obj).getScheme());
    }

    @Override // com.bumptech.glide.load.model.r
    public final q b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) {
        com.bumptech.glide.load.data.e aVar;
        Uri uri = (Uri) obj;
        com.bumptech.glide.signature.b bVar = new com.bumptech.glide.signature.b(uri);
        C c = (C) this.a;
        switch (c.a) {
            case 0:
                aVar = new com.bumptech.glide.load.data.a(c.b, uri, 0);
                break;
            case 1:
                aVar = new com.bumptech.glide.load.data.a(c.b, uri, 1);
                break;
            default:
                aVar = new com.bumptech.glide.load.data.n(1, uri, c.b);
                break;
        }
        return new q(bVar, aVar);
    }
}
