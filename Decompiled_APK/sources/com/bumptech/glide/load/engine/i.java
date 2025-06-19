package com.bumptech.glide.load.engine;

import android.util.Log;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.bumptech.glide.Registry$MissingComponentException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/* loaded from: classes.dex */
public final class i {
    public final Class a;
    public final List b;
    public final com.bumptech.glide.load.resource.transcode.b c;
    public final com.quizlet.data.repository.course.membership.c d;
    public final String e;

    public i(Class cls, Class cls2, Class cls3, List list, com.bumptech.glide.load.resource.transcode.b bVar, com.quizlet.data.repository.course.membership.c cVar) {
        this.a = cls;
        this.b = list;
        this.c = bVar;
        this.d = cVar;
        this.e = "Failed DecodePath{" + cls.getSimpleName() + "->" + cls2.getSimpleName() + "->" + cls3.getSimpleName() + "}";
    }

    public final v a(int i, int i2, com.android.billingclient.api.s sVar, com.bumptech.glide.load.h hVar, com.bumptech.glide.load.data.g gVar) {
        v vVarB;
        com.bumptech.glide.load.l lVar;
        int iN;
        boolean z;
        boolean z2;
        boolean z3;
        com.bumptech.glide.load.e dVar;
        com.quizlet.data.repository.course.membership.c cVar = this.d;
        List list = (List) cVar.a();
        try {
            v vVarB2 = b(gVar, i, i2, hVar, list);
            cVar.o(list);
            h hVar2 = (h) sVar.c;
            hVar2.getClass();
            Class<?> cls = vVarB2.get().getClass();
            int i3 = sVar.b;
            g gVar2 = hVar2.a;
            com.bumptech.glide.load.k kVarC = null;
            if (i3 != 4) {
                com.bumptech.glide.load.l lVarE = gVar2.e(cls);
                lVar = lVarE;
                vVarB = lVarE.b(hVar2.h, vVarB2, hVar2.l, hVar2.m);
            } else {
                vVarB = vVarB2;
                lVar = null;
            }
            if (!vVarB2.equals(vVarB)) {
                vVarB2.recycle();
            }
            if (gVar2.c.a().d.c(vVarB.c()) != null) {
                com.bumptech.glide.h hVarA = gVar2.c.a();
                hVarA.getClass();
                kVarC = hVarA.d.c(vVarB.c());
                if (kVarC == null) {
                    final Class clsC = vVarB.c();
                    throw new Registry$MissingComponentException(clsC) { // from class: com.bumptech.glide.Registry$NoResultEncoderAvailableException
                        {
                            super("Failed to find result encoder for resource class: " + clsC + ", you may need to consider registering a new Encoder for the requested type or DiskCacheStrategy.DATA/DiskCacheStrategy.NONE if caching your transformed resource is unnecessary.");
                        }
                    };
                }
                iN = kVarC.n(hVar2.o);
            } else {
                iN = 3;
            }
            com.bumptech.glide.load.k kVar = kVarC;
            com.bumptech.glide.load.e eVar = hVar2.t;
            ArrayList arrayListB = gVar2.b();
            int size = arrayListB.size();
            int i4 = 0;
            while (true) {
                if (i4 >= size) {
                    z = false;
                    break;
                }
                if (((com.bumptech.glide.load.model.q) arrayListB.get(i4)).a.equals(eVar)) {
                    z = true;
                    break;
                }
                i4++;
            }
            switch (hVar2.n.a) {
                default:
                    z2 = true;
                    if (((z || i3 != 3) && i3 != 1) || iN != 2) {
                    }
                    break;
                case 0:
                case 1:
                    z2 = false;
                    break;
            }
            if (z2) {
                if (kVar == null) {
                    final Class<?> cls2 = vVarB.get().getClass();
                    throw new Registry$MissingComponentException(cls2) { // from class: com.bumptech.glide.Registry$NoResultEncoderAvailableException
                        {
                            super("Failed to find result encoder for resource class: " + cls2 + ", you may need to consider registering a new Encoder for the requested type or DiskCacheStrategy.DATA/DiskCacheStrategy.NONE if caching your transformed resource is unnecessary.");
                        }
                    };
                }
                int iK = AbstractC0147y.k(iN);
                if (iK == 0) {
                    z3 = true;
                    dVar = new d(hVar2.t, hVar2.i);
                } else {
                    if (iK != 1) {
                        throw new IllegalArgumentException("Unknown strategy: ".concat(iN != 1 ? iN != 2 ? iN != 3 ? "null" : "NONE" : "TRANSFORMED" : "SOURCE"));
                    }
                    z3 = true;
                    dVar = new x(gVar2.c.a, hVar2.t, hVar2.i, hVar2.l, hVar2.m, lVar, cls, hVar2.o);
                }
                u uVar = (u) u.e.a();
                uVar.d = false;
                uVar.c = z3;
                uVar.b = vVarB;
                com.quizlet.data.repository.set.f fVar = hVar2.f;
                fVar.b = dVar;
                fVar.c = kVar;
                fVar.d = uVar;
                vVarB = uVar;
            }
            return this.c.d(vVarB, hVar);
        } catch (Throwable th) {
            cVar.o(list);
            throw th;
        }
    }

    public final v b(com.bumptech.glide.load.data.g gVar, int i, int i2, com.bumptech.glide.load.h hVar, List list) throws GlideException {
        List list2 = this.b;
        int size = list2.size();
        v vVarB = null;
        for (int i3 = 0; i3 < size; i3++) {
            com.bumptech.glide.load.j jVar = (com.bumptech.glide.load.j) list2.get(i3);
            try {
                if (jVar.a(gVar.l(), hVar)) {
                    vVarB = jVar.b(gVar.l(), i, i2, hVar);
                }
            } catch (IOException | OutOfMemoryError | RuntimeException e) {
                if (Log.isLoggable("DecodePath", 2)) {
                    Objects.toString(jVar);
                }
                list.add(e);
            }
            if (vVarB != null) {
                break;
            }
        }
        if (vVarB != null) {
            return vVarB;
        }
        throw new GlideException(this.e, new ArrayList(list));
    }

    public final String toString() {
        return "DecodePath{ dataClass=" + this.a + ", decoders=" + this.b + ", transcoder=" + this.c + '}';
    }
}
