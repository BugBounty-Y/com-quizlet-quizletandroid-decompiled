package com.bumptech.glide.load.model;

import android.net.Uri;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/* loaded from: classes.dex */
public final class E implements r {
    public static final Set b = Collections.unmodifiableSet(new HashSet(Arrays.asList("http", "https")));
    public final r a;

    public E(r rVar) {
        this.a = rVar;
    }

    @Override // com.bumptech.glide.load.model.r
    public final boolean a(Object obj) {
        return b.contains(((Uri) obj).getScheme());
    }

    @Override // com.bumptech.glide.load.model.r
    public final q b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) {
        return this.a.b(new h(((Uri) obj).toString()), i, i2, hVar);
    }
}
