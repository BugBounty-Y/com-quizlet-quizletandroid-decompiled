package com.bumptech.glide;

import androidx.camera.core.impl.i0;
import androidx.compose.ui.graphics.vector.C0868g;
import androidx.work.impl.model.v;
import com.bumptech.glide.load.model.r;
import com.bumptech.glide.load.model.s;
import com.bumptech.glide.load.model.t;
import com.bumptech.glide.load.model.u;
import com.bumptech.glide.load.model.x;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public final class h {
    public final u a;
    public final C0868g b;
    public final v c;
    public final i0 d;
    public final com.bumptech.glide.load.data.i e;
    public final com.android.billingclient.api.h f;
    public final com.airbnb.lottie.model.animatable.c g;
    public final androidx.work.impl.model.l h = new androidx.work.impl.model.l();
    public final com.bumptech.glide.provider.b i = new com.bumptech.glide.provider.b();
    public final com.quizlet.data.repository.course.membership.c j;

    public h() {
        com.quizlet.data.repository.course.membership.c cVar = new com.quizlet.data.repository.course.membership.c(new androidx.core.util.d(20), new com.onetrust.otpublishers.headless.Internal.Helper.h(7), new com.quizlet.shared.usecase.folderstudymaterials.a(7));
        this.j = cVar;
        this.a = new u(cVar);
        this.b = new C0868g(2);
        this.c = new v(8);
        i0 i0Var = new i0();
        i0Var.a = new ArrayList();
        this.d = i0Var;
        this.e = new com.bumptech.glide.load.data.i();
        this.f = new com.android.billingclient.api.h(1);
        this.g = new com.airbnb.lottie.model.animatable.c();
        List listAsList = Arrays.asList("Animation", "Bitmap", "BitmapDrawable");
        ArrayList arrayList = new ArrayList(listAsList.size());
        arrayList.add("legacy_prepend_all");
        Iterator it2 = listAsList.iterator();
        while (it2.hasNext()) {
            arrayList.add((String) it2.next());
        }
        arrayList.add("legacy_append");
        v vVar = this.c;
        synchronized (vVar) {
            try {
                ArrayList arrayList2 = new ArrayList((ArrayList) vVar.b);
                ((ArrayList) vVar.b).clear();
                Iterator it3 = arrayList.iterator();
                while (it3.hasNext()) {
                    ((ArrayList) vVar.b).add((String) it3.next());
                }
                Iterator it4 = arrayList2.iterator();
                while (it4.hasNext()) {
                    String str = (String) it4.next();
                    if (!arrayList.contains(str)) {
                        ((ArrayList) vVar.b).add(str);
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void a(Class cls, com.bumptech.glide.load.b bVar) {
        C0868g c0868g = this.b;
        synchronized (c0868g) {
            c0868g.a.add(new com.bumptech.glide.provider.a(cls, bVar));
        }
    }

    public final void b(Class cls, com.bumptech.glide.load.k kVar) {
        i0 i0Var = this.d;
        synchronized (i0Var) {
            i0Var.a.add(new com.bumptech.glide.provider.d(cls, kVar));
        }
    }

    public final void c(Class cls, Class cls2, s sVar) {
        u uVar = this.a;
        synchronized (uVar) {
            uVar.a.a(cls, cls2, sVar);
            uVar.b.a.clear();
        }
    }

    public final void d(String str, Class cls, Class cls2, com.bumptech.glide.load.j jVar) {
        v vVar = this.c;
        synchronized (vVar) {
            vVar.e(str).add(new com.bumptech.glide.provider.c(cls, cls2, jVar));
        }
    }

    public final ArrayList e() {
        ArrayList arrayList;
        com.airbnb.lottie.model.animatable.c cVar = this.g;
        synchronized (cVar) {
            arrayList = cVar.a;
        }
        if (arrayList.isEmpty()) {
            throw new Registry$MissingComponentException() { // from class: com.bumptech.glide.Registry$NoImageHeaderParserException
            };
        }
        return arrayList;
    }

    public final List f(Object obj) {
        List listUnmodifiableList;
        u uVar = this.a;
        uVar.getClass();
        Class<?> cls = obj.getClass();
        synchronized (uVar) {
            t tVar = (t) uVar.b.a.get(cls);
            listUnmodifiableList = tVar == null ? null : tVar.a;
            if (listUnmodifiableList == null) {
                listUnmodifiableList = Collections.unmodifiableList(uVar.a.c(cls));
                if (((t) uVar.b.a.put(cls, new t(listUnmodifiableList))) != null) {
                    throw new IllegalStateException("Already cached loaders for model: " + cls);
                }
            }
        }
        if (listUnmodifiableList.isEmpty()) {
            throw new Registry$NoModelLoaderAvailableException("Failed to find any ModelLoaders registered for model class: " + obj.getClass());
        }
        int size = listUnmodifiableList.size();
        List arrayList = Collections.EMPTY_LIST;
        boolean z = true;
        for (int i = 0; i < size; i++) {
            r rVar = (r) listUnmodifiableList.get(i);
            if (rVar.a(obj)) {
                if (z) {
                    arrayList = new ArrayList(size - i);
                    z = false;
                }
                arrayList.add(rVar);
            }
        }
        if (!arrayList.isEmpty()) {
            return arrayList;
        }
        throw new Registry$NoModelLoaderAvailableException("Found ModelLoaders for model class: " + listUnmodifiableList + ", but none that handle this specific model instance: " + obj);
    }

    public final com.bumptech.glide.load.data.g g(Object obj) {
        com.bumptech.glide.load.data.g gVarA;
        com.bumptech.glide.load.data.i iVar = this.e;
        synchronized (iVar) {
            try {
                com.bumptech.glide.util.f.b(obj);
                com.bumptech.glide.load.data.f fVar = (com.bumptech.glide.load.data.f) ((HashMap) iVar.b).get(obj.getClass());
                if (fVar == null) {
                    Iterator it2 = ((HashMap) iVar.b).values().iterator();
                    while (true) {
                        if (!it2.hasNext()) {
                            break;
                        }
                        com.bumptech.glide.load.data.f fVar2 = (com.bumptech.glide.load.data.f) it2.next();
                        if (fVar2.getDataClass().isAssignableFrom(obj.getClass())) {
                            fVar = fVar2;
                            break;
                        }
                    }
                }
                if (fVar == null) {
                    fVar = com.bumptech.glide.load.data.i.c;
                }
                gVarA = fVar.a(obj);
            } catch (Throwable th) {
                throw th;
            }
        }
        return gVarA;
    }

    public final void h(com.bumptech.glide.load.data.f fVar) {
        com.bumptech.glide.load.data.i iVar = this.e;
        synchronized (iVar) {
            ((HashMap) iVar.b).put(fVar.getDataClass(), fVar);
        }
    }

    public final void i(Class cls, Class cls2, com.bumptech.glide.load.resource.transcode.b bVar) {
        com.android.billingclient.api.h hVar = this.f;
        synchronized (hVar) {
            hVar.a.add(new com.bumptech.glide.load.resource.transcode.c(cls, cls2, bVar));
        }
    }

    public final void j(com.bumptech.glide.integration.okhttp3.b bVar) {
        ArrayList arrayListE;
        u uVar = this.a;
        synchronized (uVar) {
            x xVar = uVar.a;
            synchronized (xVar) {
                arrayListE = xVar.e();
                xVar.a(com.bumptech.glide.load.model.h.class, InputStream.class, bVar);
            }
            Iterator it2 = arrayListE.iterator();
            while (it2.hasNext()) {
                ((s) it2.next()).getClass();
            }
            uVar.b.a.clear();
        }
    }
}
