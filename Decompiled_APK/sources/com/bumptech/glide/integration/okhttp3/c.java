package com.bumptech.glide.integration.okhttp3;

import com.bumptech.glide.load.h;
import com.bumptech.glide.load.model.C1535c;
import com.bumptech.glide.load.model.n;
import com.bumptech.glide.load.model.q;
import com.bumptech.glide.load.model.r;
import java.io.File;
import okhttp3.InterfaceC5075d;

/* loaded from: classes.dex */
public final class c implements r {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.bumptech.glide.load.model.r
    public final boolean a(Object obj) {
        switch (this.a) {
            case 0:
                return true;
            case 1:
                return true;
            case 2:
                return obj.toString().startsWith("data:image");
            default:
                return true;
        }
    }

    @Override // com.bumptech.glide.load.model.r
    public final q b(Object obj, int i, int i2, h hVar) {
        switch (this.a) {
            case 0:
                com.bumptech.glide.load.model.h hVar2 = (com.bumptech.glide.load.model.h) obj;
                return new q(hVar2, new a((InterfaceC5075d) this.b, hVar2));
            case 1:
                byte[] bArr = (byte[]) obj;
                return new q(new com.bumptech.glide.signature.b(bArr), new n(1, bArr, (C1535c) this.b));
            case 2:
                return new q(new com.bumptech.glide.signature.b(obj), new com.bumptech.glide.load.data.mediastore.b(1, obj.toString(), (C1535c) this.b));
            default:
                File file = (File) obj;
                return new q(new com.bumptech.glide.signature.b(file), new com.bumptech.glide.load.data.mediastore.b(2, file, (C1535c) this.b));
        }
    }
}
