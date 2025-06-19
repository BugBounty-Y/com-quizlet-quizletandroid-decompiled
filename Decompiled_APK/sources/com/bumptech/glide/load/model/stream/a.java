package com.bumptech.glide.load.model.stream;

import com.bumptech.glide.load.data.l;
import com.bumptech.glide.load.model.o;
import com.bumptech.glide.load.model.p;
import com.bumptech.glide.load.model.q;
import com.bumptech.glide.load.model.r;
import java.util.ArrayDeque;

/* loaded from: classes.dex */
public final class a implements r {
    public static final com.bumptech.glide.load.g b = com.bumptech.glide.load.g.a(2500, "com.bumptech.glide.load.model.stream.HttpGlideUrlLoader.Timeout");
    public final com.google.firebase.platforminfo.c a;

    public a(com.google.firebase.platforminfo.c cVar) {
        this.a = cVar;
    }

    @Override // com.bumptech.glide.load.model.r
    public final /* bridge */ /* synthetic */ boolean a(Object obj) {
        return true;
    }

    @Override // com.bumptech.glide.load.model.r
    public final q b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) {
        com.bumptech.glide.load.model.h hVar2 = (com.bumptech.glide.load.model.h) obj;
        com.google.firebase.platforminfo.c cVar = this.a;
        if (cVar != null) {
            p pVarA = p.a(hVar2);
            o oVar = (o) cVar.a;
            Object objA = oVar.a(pVarA);
            ArrayDeque arrayDeque = p.b;
            synchronized (arrayDeque) {
                arrayDeque.offer(pVarA);
            }
            com.bumptech.glide.load.model.h hVar3 = (com.bumptech.glide.load.model.h) objA;
            if (hVar3 == null) {
                oVar.f(p.a(hVar2), hVar2);
            } else {
                hVar2 = hVar3;
            }
        }
        return new q(hVar2, new l(hVar2, ((Integer) hVar.c(b)).intValue()));
    }
}
