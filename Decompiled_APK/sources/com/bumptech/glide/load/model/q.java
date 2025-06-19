package com.bumptech.glide.load.model;

import java.util.Collections;
import java.util.List;

/* loaded from: classes.dex */
public final class q {
    public final com.bumptech.glide.load.e a;
    public final List b;
    public final com.bumptech.glide.load.data.e c;

    public q(com.bumptech.glide.load.e eVar, com.bumptech.glide.load.data.e eVar2) {
        List list = Collections.EMPTY_LIST;
        com.bumptech.glide.util.f.c(eVar, "Argument must not be null");
        this.a = eVar;
        com.bumptech.glide.util.f.c(list, "Argument must not be null");
        this.b = list;
        com.bumptech.glide.util.f.c(eVar2, "Argument must not be null");
        this.c = eVar2;
    }
}
