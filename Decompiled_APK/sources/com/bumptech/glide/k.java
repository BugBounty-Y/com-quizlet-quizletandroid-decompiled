package com.bumptech.glide;

import android.content.Context;
import android.util.Log;
import androidx.collection.C0203a;
import androidx.collection.C0208f;
import com.google.android.gms.internal.measurement.C3083y1;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/* loaded from: classes.dex */
public final class k extends com.bumptech.glide.request.a {
    public boolean A;
    public boolean B;
    public final Context q;
    public final m r;
    public final Class s;
    public final e t;
    public a u;
    public Object v;
    public ArrayList w;
    public k x;
    public k y;
    public final boolean z = true;

    static {
    }

    public k(Glide glide, m mVar, Class cls, Context context) {
        com.bumptech.glide.request.f fVar;
        this.r = mVar;
        this.s = cls;
        this.q = context;
        C0208f c0208f = mVar.a.c.f;
        a aVar = (a) c0208f.get(cls);
        if (aVar == null) {
            Iterator it2 = ((C0203a) c0208f.entrySet()).iterator();
            while (it2.hasNext()) {
                Map.Entry entry = (Map.Entry) it2.next();
                if (((Class) entry.getKey()).isAssignableFrom(cls)) {
                    aVar = (a) entry.getValue();
                }
            }
        }
        this.u = aVar == null ? e.k : aVar;
        this.t = glide.c;
        Iterator it3 = mVar.i.iterator();
        while (it3.hasNext()) {
            v((com.bumptech.glide.request.e) it3.next());
        }
        synchronized (mVar) {
            fVar = mVar.j;
        }
        b(fVar);
    }

    public final void A(com.bumptech.glide.request.target.e eVar, com.bumptech.glide.request.a aVar) {
        com.bumptech.glide.util.f.b(eVar);
        if (!this.A) {
            throw new IllegalArgumentException("You must call #load() before calling #into()");
        }
        com.bumptech.glide.request.c cVarX = x(new Object(), eVar, null, this.u, aVar.c, aVar.g, aVar.f, aVar);
        com.bumptech.glide.request.c cVarB = eVar.b();
        if (cVarX.c(cVarB) && (aVar.e || !cVarB.i())) {
            com.bumptech.glide.util.f.c(cVarB, "Argument must not be null");
            if (cVarB.isRunning()) {
                return;
            }
            cVarB.g();
            return;
        }
        this.r.i(eVar);
        eVar.d(cVarX);
        m mVar = this.r;
        synchronized (mVar) {
            mVar.f.a.add(eVar);
            C3083y1 c3083y1 = mVar.d;
            ((Set) c3083y1.c).add(cVarX);
            if (c3083y1.b) {
                cVarX.clear();
                Log.isLoggable("RequestTracker", 2);
                ((HashSet) c3083y1.d).add(cVarX);
            } else {
                cVarX.g();
            }
        }
    }

    public final k B(com.bumptech.glide.request.e eVar) {
        if (this.n) {
            return clone().B(eVar);
        }
        this.w = null;
        return v(eVar);
    }

    public final k D(Object obj) {
        if (this.n) {
            return clone().D(obj);
        }
        this.v = obj;
        this.A = true;
        n();
        return this;
    }

    @Override // com.bumptech.glide.request.a
    public final boolean equals(Object obj) {
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        if (super.equals(kVar)) {
            return Objects.equals(this.s, kVar.s) && this.u.equals(kVar.u) && Objects.equals(this.v, kVar.v) && Objects.equals(this.w, kVar.w) && Objects.equals(this.x, kVar.x) && Objects.equals(this.y, kVar.y) && this.z == kVar.z && this.A == kVar.A;
        }
        return false;
    }

    @Override // com.bumptech.glide.request.a
    public final int hashCode() {
        return com.bumptech.glide.util.m.g(this.A ? 1 : 0, com.bumptech.glide.util.m.g(this.z ? 1 : 0, com.bumptech.glide.util.m.h(com.bumptech.glide.util.m.h(com.bumptech.glide.util.m.h(com.bumptech.glide.util.m.h(com.bumptech.glide.util.m.h(com.bumptech.glide.util.m.h(com.bumptech.glide.util.m.h(super.hashCode(), this.s), this.u), this.v), this.w), this.x), this.y), null)));
    }

    public final k v(com.bumptech.glide.request.e eVar) {
        if (this.n) {
            return clone().v(eVar);
        }
        if (eVar != null) {
            if (this.w == null) {
                this.w = new ArrayList();
            }
            this.w.add(eVar);
        }
        n();
        return this;
    }

    @Override // com.bumptech.glide.request.a
    /* renamed from: w, reason: merged with bridge method [inline-methods] */
    public final k b(com.bumptech.glide.request.a aVar) {
        com.bumptech.glide.util.f.b(aVar);
        return (k) super.b(aVar);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final com.bumptech.glide.request.c x(Object obj, com.bumptech.glide.request.target.e eVar, com.bumptech.glide.request.d dVar, a aVar, g gVar, int i, int i2, com.bumptech.glide.request.a aVar2) {
        com.bumptech.glide.request.d dVar2;
        com.bumptech.glide.request.d bVar;
        com.bumptech.glide.request.a aVar3;
        com.bumptech.glide.request.g gVar2;
        g gVar3;
        if (this.y != null) {
            bVar = new com.bumptech.glide.request.b(obj, dVar);
            dVar2 = bVar;
        } else {
            dVar2 = null;
            bVar = dVar;
        }
        k kVar = this.x;
        if (kVar == null) {
            Object obj2 = this.v;
            ArrayList arrayList = this.w;
            e eVar2 = this.t;
            aVar3 = aVar2;
            gVar2 = new com.bumptech.glide.request.g(this.q, eVar2, obj, obj2, this.s, aVar3, i, i2, gVar, eVar, arrayList, bVar, eVar2.g, aVar.a);
        } else {
            if (this.B) {
                throw new IllegalStateException("You cannot use a request as both the main request and a thumbnail, consider using clone() on the request(s) passed to thumbnail()");
            }
            a aVar4 = kVar.z ? aVar : kVar.u;
            if (com.bumptech.glide.request.a.g(kVar.a, 8)) {
                gVar3 = this.x.c;
            } else {
                int iOrdinal = gVar.ordinal();
                if (iOrdinal == 0 || iOrdinal == 1) {
                    gVar3 = g.a;
                } else if (iOrdinal == 2) {
                    gVar3 = g.b;
                } else {
                    if (iOrdinal != 3) {
                        throw new IllegalArgumentException("unknown priority: " + this.c);
                    }
                    gVar3 = g.c;
                }
            }
            g gVar4 = gVar3;
            k kVar2 = this.x;
            int i3 = kVar2.g;
            int i4 = kVar2.f;
            if (com.bumptech.glide.util.m.i(i, i2)) {
                k kVar3 = this.x;
                if (!com.bumptech.glide.util.m.i(kVar3.g, kVar3.f)) {
                    i3 = aVar2.g;
                    i4 = aVar2.f;
                }
            }
            int i5 = i4;
            int i6 = i3;
            com.bumptech.glide.request.h hVar = new com.bumptech.glide.request.h(obj, bVar);
            Object obj3 = this.v;
            ArrayList arrayList2 = this.w;
            com.bumptech.glide.request.h hVar2 = hVar;
            e eVar3 = this.t;
            com.bumptech.glide.request.g gVar5 = new com.bumptech.glide.request.g(this.q, eVar3, obj, obj3, this.s, aVar2, i, i2, gVar, eVar, arrayList2, hVar2, eVar3.g, aVar.a);
            this.B = true;
            k kVar4 = this.x;
            com.bumptech.glide.request.c cVarX = kVar4.x(obj, eVar, hVar2, aVar4, gVar4, i6, i5, kVar4);
            this.B = false;
            hVar2.c = gVar5;
            hVar2.d = cVarX;
            aVar3 = aVar2;
            gVar2 = hVar2;
        }
        if (dVar2 == null) {
            return gVar2;
        }
        k kVar5 = this.y;
        int i7 = kVar5.g;
        int i8 = kVar5.f;
        if (com.bumptech.glide.util.m.i(i, i2)) {
            k kVar6 = this.y;
            if (!com.bumptech.glide.util.m.i(kVar6.g, kVar6.f)) {
                i7 = aVar3.g;
                i8 = aVar3.f;
            }
        }
        int i9 = i8;
        k kVar7 = this.y;
        com.bumptech.glide.request.b bVar2 = dVar2;
        com.bumptech.glide.request.c cVarX2 = kVar7.x(obj, eVar, bVar2, kVar7.u, kVar7.c, i7, i9, kVar7);
        bVar2.c = gVar2;
        bVar2.d = cVarX2;
        return bVar2;
    }

    @Override // com.bumptech.glide.request.a
    /* renamed from: y, reason: merged with bridge method [inline-methods] */
    public final k clone() {
        k kVar = (k) super.clone();
        kVar.u = kVar.u.clone();
        if (kVar.w != null) {
            kVar.w = new ArrayList(kVar.w);
        }
        k kVar2 = kVar.x;
        if (kVar2 != null) {
            kVar.x = kVar2.clone();
        }
        k kVar3 = kVar.y;
        if (kVar3 != null) {
            kVar.y = kVar3.clone();
        }
        return kVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0067  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void z(android.widget.ImageView r5) {
        /*
            r4 = this;
            com.bumptech.glide.util.m.a()
            com.bumptech.glide.util.f.b(r5)
            int r0 = r4.a
            r1 = 2048(0x800, float:2.87E-42)
            boolean r0 = com.bumptech.glide.request.a.g(r0, r1)
            if (r0 != 0) goto L67
            android.widget.ImageView$ScaleType r0 = r5.getScaleType()
            if (r0 == 0) goto L67
            int[] r0 = com.bumptech.glide.j.a
            android.widget.ImageView$ScaleType r1 = r5.getScaleType()
            int r1 = r1.ordinal()
            r0 = r0[r1]
            r1 = 0
            switch(r0) {
                case 1: goto L57;
                case 2: goto L47;
                case 3: goto L37;
                case 4: goto L37;
                case 5: goto L37;
                case 6: goto L27;
                default: goto L26;
            }
        L26:
            goto L67
        L27:
            com.bumptech.glide.k r0 = r4.clone()
            com.bumptech.glide.load.resource.bitmap.m r2 = com.bumptech.glide.load.resource.bitmap.m.c
            com.bumptech.glide.load.resource.bitmap.i r3 = new com.bumptech.glide.load.resource.bitmap.i
            r3.<init>()
            com.bumptech.glide.request.a r0 = r0.m(r2, r3, r1)
            goto L68
        L37:
            com.bumptech.glide.k r0 = r4.clone()
            com.bumptech.glide.load.resource.bitmap.m r2 = com.bumptech.glide.load.resource.bitmap.m.b
            com.bumptech.glide.load.resource.bitmap.t r3 = new com.bumptech.glide.load.resource.bitmap.t
            r3.<init>()
            com.bumptech.glide.request.a r0 = r0.m(r2, r3, r1)
            goto L68
        L47:
            com.bumptech.glide.k r0 = r4.clone()
            com.bumptech.glide.load.resource.bitmap.m r2 = com.bumptech.glide.load.resource.bitmap.m.c
            com.bumptech.glide.load.resource.bitmap.i r3 = new com.bumptech.glide.load.resource.bitmap.i
            r3.<init>()
            com.bumptech.glide.request.a r0 = r0.m(r2, r3, r1)
            goto L68
        L57:
            com.bumptech.glide.k r0 = r4.clone()
            com.bumptech.glide.load.resource.bitmap.m r1 = com.bumptech.glide.load.resource.bitmap.m.d
            com.bumptech.glide.load.resource.bitmap.h r2 = new com.bumptech.glide.load.resource.bitmap.h
            r2.<init>()
            com.bumptech.glide.request.a r0 = r0.h(r1, r2)
            goto L68
        L67:
            r0 = r4
        L68:
            com.bumptech.glide.e r1 = r4.t
            com.google.mlkit.common.sdkinternal.b r1 = r1.c
            r1.getClass()
            java.lang.Class<android.graphics.Bitmap> r1 = android.graphics.Bitmap.class
            java.lang.Class r2 = r4.s
            boolean r1 = r1.equals(r2)
            if (r1 == 0) goto L80
            com.bumptech.glide.request.target.a r1 = new com.bumptech.glide.request.target.a
            r2 = 0
            r1.<init>(r5, r2)
            goto L8e
        L80:
            java.lang.Class<android.graphics.drawable.Drawable> r1 = android.graphics.drawable.Drawable.class
            boolean r1 = r1.isAssignableFrom(r2)
            if (r1 == 0) goto L92
            com.bumptech.glide.request.target.a r1 = new com.bumptech.glide.request.target.a
            r2 = 1
            r1.<init>(r5, r2)
        L8e:
            r4.A(r1, r0)
            return
        L92:
            java.lang.IllegalArgumentException r5 = new java.lang.IllegalArgumentException
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r1 = "Unhandled class: "
            r0.<init>(r1)
            r0.append(r2)
            java.lang.String r1 = ", try .as*(Class).transcode(ResourceTranscoder)"
            r0.append(r1)
            java.lang.String r0 = r0.toString()
            r5.<init>(r0)
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.bumptech.glide.k.z(android.widget.ImageView):void");
    }
}
