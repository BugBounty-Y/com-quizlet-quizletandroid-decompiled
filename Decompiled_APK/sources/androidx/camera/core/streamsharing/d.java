package androidx.camera.core.streamsharing;

import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.RectF;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraDevice;
import android.util.Log;
import android.util.Size;
import androidx.activity.RunnableC0041m;
import androidx.appcompat.app.L;
import androidx.camera.camera2.internal.K;
import androidx.camera.camera2.internal.RunnableC0130g;
import androidx.camera.camera2.internal.RunnableC0141s;
import androidx.camera.camera2.internal.s0;
import androidx.camera.core.ProcessingException;
import androidx.camera.core.Q;
import androidx.camera.core.a0;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.AbstractC0171j;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.C0168g;
import androidx.camera.core.impl.D0;
import androidx.camera.core.impl.F;
import androidx.camera.core.impl.H;
import androidx.camera.core.impl.InterfaceC0185y;
import androidx.camera.core.impl.O;
import androidx.camera.core.impl.P;
import androidx.camera.core.impl.X;
import androidx.camera.core.impl.m0;
import androidx.camera.core.impl.n0;
import androidx.camera.core.impl.q0;
import androidx.camera.core.impl.z0;
import androidx.camera.core.l0;
import androidx.camera.core.processing.k;
import androidx.camera.core.processing.m;
import androidx.camera.core.processing.n;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/* loaded from: classes.dex */
public final class d extends l0 {
    public n0 A;
    public final e o;
    public final g p;
    public final Q q;
    public final Q r;
    public io.ktor.client.plugins.api.d s;
    public com.quizlet.data.repository.folderwithcreatorinclass.e t;
    public k u;
    public k v;
    public k w;
    public k x;
    public m0 y;
    public m0 z;

    public d(InterfaceC0185y interfaceC0185y, InterfaceC0185y interfaceC0185y2, Q q, Q q2, HashSet hashSet, K k) {
        super(G(hashSet));
        this.o = G(hashSet);
        this.q = q;
        this.r = q2;
        this.p = new g(interfaceC0185y, interfaceC0185y2, hashSet, k, new s0(2));
    }

    public static ArrayList F(l0 l0Var) {
        ArrayList arrayList = new ArrayList();
        if (!(l0Var instanceof d)) {
            arrayList.add(l0Var.f.x());
            return arrayList;
        }
        Iterator it2 = ((d) l0Var).p.a.iterator();
        while (it2.hasNext()) {
            arrayList.add(((l0) it2.next()).f.x());
        }
        return arrayList;
    }

    public static e G(HashSet hashSet) {
        X xB = X.b();
        new L(xB);
        xB.m(O.b0, 34);
        ArrayList arrayList = new ArrayList();
        Iterator it2 = hashSet.iterator();
        while (it2.hasNext()) {
            l0 l0Var = (l0) it2.next();
            if (l0Var.f.c(A0.v0)) {
                arrayList.add(l0Var.f.x());
            } else {
                Log.e("StreamSharing", "A child does not have capture type.");
            }
        }
        xB.m(e.b, arrayList);
        xB.m(P.g0, 2);
        return new e(C0163c0.a(xB));
    }

    public final void B() {
        n0 n0Var = this.A;
        if (n0Var != null) {
            n0Var.b();
            this.A = null;
        }
        k kVar = this.u;
        if (kVar != null) {
            kVar.b();
            this.u = null;
        }
        k kVar2 = this.v;
        if (kVar2 != null) {
            kVar2.b();
            this.v = null;
        }
        k kVar3 = this.w;
        if (kVar3 != null) {
            kVar3.b();
            this.w = null;
        }
        k kVar4 = this.x;
        if (kVar4 != null) {
            kVar4.b();
            this.x = null;
        }
        io.ktor.client.plugins.api.d dVar = this.s;
        if (dVar != null) {
            ((androidx.camera.core.processing.c) dVar.b).a();
            S.g(new RunnableC0041m(dVar, 22));
            this.s = null;
        }
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.t;
        if (eVar != null) {
            ((m) eVar.a).a();
            S.g(new RunnableC0041m(eVar, 24));
            this.t = null;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final List C(String str, String str2, A0 a0, C0168g c0168g, C0168g c0168g2) {
        boolean z;
        S.d();
        g gVar = this.p;
        int i = 0;
        if (c0168g2 == null) {
            D(str, str2, a0, c0168g, null);
            InterfaceC0185y interfaceC0185yB = b();
            Objects.requireNonNull(interfaceC0185yB);
            this.s = new io.ktor.client.plugins.api.d(interfaceC0185yB, new androidx.camera.core.processing.c(c0168g.b));
            boolean z2 = this.i != null;
            k kVar = this.w;
            int iV = ((P) this.f).v();
            gVar.getClass();
            HashMap map = new HashMap();
            Iterator it2 = gVar.a.iterator();
            while (it2.hasNext()) {
                l0 l0Var = (l0) it2.next();
                b bVar = gVar.k;
                InterfaceC0185y interfaceC0185y = gVar.f;
                g gVar2 = gVar;
                boolean z3 = z2;
                map.put(l0Var, gVar2.p(l0Var, bVar, interfaceC0185y, kVar, iV, z3));
                z2 = z3;
                gVar = gVar2;
            }
            g gVar3 = gVar;
            io.ktor.client.plugins.api.d dVar = this.s;
            k kVar2 = this.w;
            ArrayList arrayList = new ArrayList(map.values());
            if (kVar2 == null) {
                throw new NullPointerException("Null surfaceEdge");
            }
            dVar.getClass();
            S.d();
            dVar.d = new n();
            Iterator it3 = arrayList.iterator();
            while (it3.hasNext()) {
                androidx.camera.core.processing.util.b bVar2 = (androidx.camera.core.processing.util.b) it3.next();
                n nVar = (n) dVar.d;
                Rect rect = bVar2.d;
                Matrix matrix = new Matrix(kVar2.b);
                RectF rectF = new RectF(rect);
                RectF rectF2 = androidx.camera.core.impl.utils.f.a;
                float f = i;
                Size size = bVar2.e;
                Iterator it4 = it3;
                RectF rectF3 = new RectF(f, f, size.getWidth(), size.getHeight());
                int i2 = bVar2.f;
                boolean z4 = bVar2.g;
                matrix.postConcat(androidx.camera.core.impl.utils.f.a(rectF, rectF3, i2, z4));
                AbstractC3242q6.d(androidx.camera.core.impl.utils.f.c(androidx.camera.core.impl.utils.f.e(androidx.camera.core.impl.utils.f.d(rect), i2), false, size));
                Rect rect2 = new Rect(0, 0, size.getWidth(), size.getHeight());
                com.quizlet.data.interactor.folderwithcreator.m mVarA = kVar2.g.a();
                mVarA.a = size;
                nVar.put(bVar2, new k(bVar2.b, bVar2.c, mVarA.d(), matrix, false, rect2, kVar2.i - i2, -1, kVar2.e != z4));
                it3 = it4;
                i = 0;
            }
            try {
                ((androidx.camera.core.processing.c) dVar.b).c(kVar2.c((InterfaceC0185y) dVar.c, true));
            } catch (ProcessingException e) {
                AbstractC3053s1.d("SurfaceProcessorNode", "Failed to send SurfaceRequest to SurfaceProcessor.", e);
            }
            for (Map.Entry entry : ((n) dVar.d).entrySet()) {
                dVar.h(kVar2, entry);
                k kVar3 = (k) entry.getValue();
                RunnableC0130g runnableC0130g = new RunnableC0130g(dVar, kVar2, entry, 6);
                kVar3.getClass();
                S.d();
                kVar3.a();
                kVar3.m.add(runnableC0130g);
            }
            kVar2.o.add(new androidx.camera.core.imagecapture.c((n) dVar.d, 1));
            n nVar2 = (n) dVar.d;
            HashMap map2 = new HashMap();
            for (Map.Entry entry2 : map.entrySet()) {
                map2.put((l0) entry2.getKey(), (k) nVar2.get(entry2.getValue()));
            }
            gVar3.t(map2);
            Object[] objArr = {this.y.c()};
            ArrayList arrayList2 = new ArrayList(1);
            Object obj = objArr[0];
            Objects.requireNonNull(obj);
            arrayList2.add(obj);
            return Collections.unmodifiableList(arrayList2);
        }
        D(str, str2, a0, c0168g, c0168g2);
        Matrix matrix2 = this.j;
        InterfaceC0185y interfaceC0185yH = h();
        Objects.requireNonNull(interfaceC0185yH);
        boolean zL = interfaceC0185yH.l();
        Rect rect3 = this.i;
        if (rect3 != null) {
            z = false;
        } else {
            Size size2 = c0168g2.a;
            z = false;
            rect3 = new Rect(0, 0, size2.getWidth(), size2.getHeight());
        }
        Rect rect4 = rect3;
        InterfaceC0185y interfaceC0185yH2 = h();
        Objects.requireNonNull(interfaceC0185yH2);
        int iG = g(interfaceC0185yH2, z);
        InterfaceC0185y interfaceC0185yH3 = h();
        Objects.requireNonNull(interfaceC0185yH3);
        g gVar4 = gVar;
        k kVar4 = new k(3, 34, c0168g2, matrix2, zL, rect4, iG, -1, k(interfaceC0185yH3));
        this.v = kVar4;
        Objects.requireNonNull(h());
        this.x = kVar4;
        m0 m0VarE = E(this.v, a0, c0168g2);
        this.z = m0VarE;
        n0 n0Var = this.A;
        if (n0Var != null) {
            n0Var.b();
        }
        n0 n0Var2 = new n0(new c(this, str, str2, a0, c0168g, c0168g2));
        this.A = n0Var2;
        m0VarE.f = n0Var2;
        this.t = new com.quizlet.data.repository.folderwithcreatorinclass.e(b(), h(), new androidx.camera.core.processing.concurrent.e(c0168g.b, this.q, this.r));
        boolean z5 = this.i != null;
        k kVar5 = this.w;
        k kVar6 = this.x;
        int iV2 = ((P) this.f).v();
        gVar4.getClass();
        HashMap map3 = new HashMap();
        Iterator it5 = gVar4.a.iterator();
        while (it5.hasNext()) {
            l0 l0Var2 = (l0) it5.next();
            g gVar5 = gVar4;
            androidx.camera.core.processing.util.b bVarP = gVar5.p(l0Var2, gVar4.k, gVar4.f, kVar5, iV2, z5);
            k kVar7 = kVar5;
            InterfaceC0185y interfaceC0185y2 = gVar5.g;
            Objects.requireNonNull(interfaceC0185y2);
            k kVar8 = kVar6;
            map3.put(l0Var2, new androidx.camera.core.processing.concurrent.a(bVarP, gVar5.p(l0Var2, gVar5.l, interfaceC0185y2, kVar8, iV2, z5)));
            gVar4 = gVar5;
            kVar6 = kVar8;
            kVar5 = kVar7;
        }
        g gVar6 = gVar4;
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.t;
        androidx.camera.core.processing.concurrent.b bVar3 = new androidx.camera.core.processing.concurrent.b(this.w, this.x, new ArrayList(map3.values()));
        eVar.getClass();
        m mVar = (m) eVar.a;
        S.d();
        eVar.e = bVar3;
        eVar.d = new n();
        androidx.camera.core.processing.concurrent.b bVar4 = (androidx.camera.core.processing.concurrent.b) eVar.e;
        k kVar9 = bVar4.a;
        Iterator it6 = bVar4.c.iterator();
        while (it6.hasNext()) {
            androidx.camera.core.processing.concurrent.a aVar = (androidx.camera.core.processing.concurrent.a) it6.next();
            n nVar3 = (n) eVar.d;
            androidx.camera.core.processing.util.b bVar5 = aVar.a;
            Matrix matrix3 = new Matrix();
            Size sizeD = androidx.camera.core.impl.utils.f.d(bVar5.d);
            int i3 = bVar5.f;
            Size sizeE = androidx.camera.core.impl.utils.f.e(sizeD, i3);
            Size size3 = bVar5.e;
            HashMap map4 = map3;
            AbstractC3242q6.d(androidx.camera.core.impl.utils.f.c(sizeE, false, size3));
            Iterator it7 = it6;
            Rect rect5 = new Rect(0, 0, size3.getWidth(), size3.getHeight());
            com.quizlet.data.interactor.folderwithcreator.m mVarA2 = kVar9.g.a();
            mVarA2.a = size3;
            nVar3.put(aVar, new k(bVar5.b, bVar5.c, mVarA2.d(), matrix3, false, rect5, kVar9.i - i3, -1, kVar9.e != bVar5.g));
            map3 = map4;
            it6 = it7;
        }
        HashMap map5 = map3;
        try {
            mVar.c(kVar9.c((InterfaceC0185y) eVar.b, true));
        } catch (ProcessingException e2) {
            AbstractC3053s1.d("DualSurfaceProcessorNode", "Failed to send SurfaceRequest to SurfaceProcessor.", e2);
        }
        k kVar10 = bVar4.b;
        try {
            mVar.c(kVar10.c((InterfaceC0185y) eVar.c, false));
        } catch (ProcessingException e3) {
            AbstractC3053s1.d("DualSurfaceProcessorNode", "Failed to send SurfaceRequest to SurfaceProcessor.", e3);
        }
        for (Map.Entry entry3 : ((n) eVar.d).entrySet()) {
            InterfaceC0185y interfaceC0185y3 = (InterfaceC0185y) eVar.b;
            InterfaceC0185y interfaceC0185y4 = (InterfaceC0185y) eVar.c;
            k kVar11 = kVar10;
            k kVar12 = kVar9;
            eVar.d(interfaceC0185y3, interfaceC0185y4, kVar12, kVar11, entry3);
            k kVar13 = (k) entry3.getValue();
            com.quizlet.data.repository.folderwithcreatorinclass.e eVar2 = eVar;
            RunnableC0141s runnableC0141s = new RunnableC0141s(eVar2, interfaceC0185y3, interfaceC0185y4, kVar12, kVar11, entry3, 1);
            eVar = eVar2;
            kVar13.getClass();
            S.d();
            kVar13.a();
            kVar13.m.add(runnableC0141s);
            kVar9 = kVar12;
            kVar10 = kVar11;
        }
        n nVar4 = (n) eVar.d;
        HashMap map6 = new HashMap();
        for (Map.Entry entry4 : map5.entrySet()) {
            map6.put((l0) entry4.getKey(), (k) nVar4.get(entry4.getValue()));
        }
        gVar6.t(map6);
        Object[] objArr2 = {this.y.c(), this.z.c()};
        ArrayList arrayList3 = new ArrayList(2);
        for (int i4 = 0; i4 < 2; i4++) {
            Object obj2 = objArr2[i4];
            Objects.requireNonNull(obj2);
            arrayList3.add(obj2);
        }
        return Collections.unmodifiableList(arrayList3);
    }

    public final void D(String str, String str2, A0 a0, C0168g c0168g, C0168g c0168g2) {
        Matrix matrix = this.j;
        InterfaceC0185y interfaceC0185yB = b();
        Objects.requireNonNull(interfaceC0185yB);
        boolean zL = interfaceC0185yB.l();
        Size size = c0168g.a;
        Rect rect = this.i;
        if (rect == null) {
            rect = new Rect(0, 0, size.getWidth(), size.getHeight());
        }
        InterfaceC0185y interfaceC0185yB2 = b();
        Objects.requireNonNull(interfaceC0185yB2);
        int iG = g(interfaceC0185yB2, false);
        InterfaceC0185y interfaceC0185yB3 = b();
        Objects.requireNonNull(interfaceC0185yB3);
        k kVar = new k(3, 34, c0168g, matrix, zL, rect, iG, -1, k(interfaceC0185yB3));
        this.u = kVar;
        Objects.requireNonNull(b());
        this.w = kVar;
        m0 m0VarE = E(this.u, a0, c0168g);
        this.y = m0VarE;
        n0 n0Var = this.A;
        if (n0Var != null) {
            n0Var.b();
        }
        n0 n0Var2 = new n0(new c(this, str, str2, a0, c0168g, c0168g2));
        this.A = n0Var2;
        m0VarE.f = n0Var2;
    }

    public final m0 E(k kVar, A0 a0, C0168g c0168g) {
        m0 m0VarD = m0.d(a0, c0168g.a);
        g gVar = this.p;
        Iterator it2 = gVar.a.iterator();
        int i = -1;
        while (it2.hasNext()) {
            int i2 = ((q0) ((l0) it2.next()).f.e(A0.n0)).g.c;
            Integer numValueOf = Integer.valueOf(i);
            List list = q0.i;
            if (list.indexOf(numValueOf) < list.indexOf(Integer.valueOf(i2))) {
                i = i2;
            }
        }
        a0 a0Var = m0VarD.b;
        if (i != -1) {
            a0Var.a = i;
        }
        Iterator it3 = gVar.a.iterator();
        while (it3.hasNext()) {
            q0 q0VarC = m0.d(((l0) it3.next()).f, c0168g.a).c();
            F f = q0VarC.g;
            a0Var.a(f.d);
            for (AbstractC0171j abstractC0171j : q0VarC.e) {
                a0Var.c(abstractC0171j);
                ArrayList arrayList = m0VarD.e;
                if (!arrayList.contains(abstractC0171j)) {
                    arrayList.add(abstractC0171j);
                }
            }
            for (CameraCaptureSession.StateCallback stateCallback : q0VarC.d) {
                ArrayList arrayList2 = m0VarD.d;
                if (!arrayList2.contains(stateCallback)) {
                    arrayList2.add(stateCallback);
                }
            }
            for (CameraDevice.StateCallback stateCallback2 : q0VarC.c) {
                ArrayList arrayList3 = m0VarD.c;
                if (!arrayList3.contains(stateCallback2)) {
                    arrayList3.add(stateCallback2);
                }
            }
            a0Var.d(f.b);
        }
        kVar.getClass();
        S.d();
        kVar.a();
        AbstractC3242q6.h("Consumer can only be linked once.", !kVar.j);
        kVar.j = true;
        m0VarD.b(kVar.l, c0168g.b, -1);
        a0Var.c(gVar.h);
        androidx.camera.camera2.impl.b bVar = c0168g.d;
        if (bVar != null) {
            a0Var.d(bVar);
        }
        return m0VarD;
    }

    @Override // androidx.camera.core.l0
    public final A0 e(boolean z, D0 d0) {
        e eVar = this.o;
        H hA = d0.a(eVar.x(), 1);
        if (z) {
            hA = H.z(hA, eVar.a);
        }
        if (hA == null) {
            return null;
        }
        return ((L) j(hA)).s();
    }

    @Override // androidx.camera.core.l0
    public final Set i() {
        HashSet hashSet = new HashSet();
        hashSet.add(3);
        return hashSet;
    }

    @Override // androidx.camera.core.l0
    public final z0 j(H h) {
        return new L(X.k(h));
    }

    @Override // androidx.camera.core.l0
    public final void p() {
        g gVar = this.p;
        Iterator it2 = gVar.a.iterator();
        while (it2.hasNext()) {
            l0 l0Var = (l0) it2.next();
            f fVar = (f) gVar.c.get(l0Var);
            Objects.requireNonNull(fVar);
            l0Var.a(fVar, null, null, l0Var.e(true, gVar.e));
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:53:0x0184  */
    @Override // androidx.camera.core.l0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.camera.core.impl.A0 r(androidx.camera.core.impl.InterfaceC0183w r13, androidx.camera.core.impl.z0 r14) {
        /*
            Method dump skipped, instructions count: 603
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.core.streamsharing.d.r(androidx.camera.core.impl.w, androidx.camera.core.impl.z0):androidx.camera.core.impl.A0");
    }

    @Override // androidx.camera.core.l0
    public final void s() {
        Iterator it2 = this.p.a.iterator();
        while (it2.hasNext()) {
            l0 l0Var = (l0) it2.next();
            l0Var.s();
            l0Var.q();
        }
    }

    @Override // androidx.camera.core.l0
    public final void t() {
        Iterator it2 = this.p.a.iterator();
        while (it2.hasNext()) {
            ((l0) it2.next()).t();
        }
    }

    @Override // androidx.camera.core.l0
    public final C0168g u(androidx.camera.camera2.impl.b bVar) {
        this.y.a(bVar);
        Object[] objArr = {this.y.c()};
        ArrayList arrayList = new ArrayList(1);
        Object obj = objArr[0];
        Objects.requireNonNull(obj);
        arrayList.add(obj);
        A(Collections.unmodifiableList(arrayList));
        com.quizlet.data.interactor.folderwithcreator.m mVarA = this.g.a();
        mVarA.d = bVar;
        return mVarA.d();
    }

    @Override // androidx.camera.core.l0
    public final C0168g v(C0168g c0168g, C0168g c0168g2) {
        A(C(d(), h() == null ? null : h().n().c(), this.f, c0168g, c0168g2));
        m();
        return c0168g;
    }

    @Override // androidx.camera.core.l0
    public final void w() {
        B();
        g gVar = this.p;
        Iterator it2 = gVar.a.iterator();
        while (it2.hasNext()) {
            l0 l0Var = (l0) it2.next();
            f fVar = (f) gVar.c.get(l0Var);
            Objects.requireNonNull(fVar);
            l0Var.z(fVar);
        }
    }
}
