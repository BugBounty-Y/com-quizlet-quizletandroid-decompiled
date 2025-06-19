package com.bumptech.glide.load.model;

import java.io.File;

/* loaded from: classes.dex */
public final class B implements r {
    public static final B b = new B(0);
    public final /* synthetic */ int a;

    public /* synthetic */ B(int i) {
        this.a = i;
    }

    @Override // com.bumptech.glide.load.model.r
    public final boolean a(Object obj) {
        switch (this.a) {
            case 0:
                return true;
            case 1:
                return true;
            default:
                return false;
        }
    }

    @Override // com.bumptech.glide.load.model.r
    public final q b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) {
        switch (this.a) {
            case 0:
                return new q(new com.bumptech.glide.signature.b(obj), new C1536d(obj, 1));
            case 1:
                File file = (File) obj;
                return new q(new com.bumptech.glide.signature.b(file), new C1536d(file, 0));
            default:
                return null;
        }
    }
}
