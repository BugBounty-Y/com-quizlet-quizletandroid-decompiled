package com.google.android.gms.internal.ads;

import android.content.Context;
import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.PointF;
import android.graphics.RectF;
import android.os.Handler;
import android.os.Looper;
import com.google.android.gms.ads.internal.overlay.AdOverlayInfoParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.ads.internal.zzl;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3460g4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

/* renamed from: com.google.android.gms.internal.ads.qn, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2538qn implements Ai {
    public boolean a;
    public final Object b;
    public final Object c;
    public final Object d;
    public final Object e;
    public final Object f;
    public final Object g;
    public final Object h;
    public final Object i;
    public final Object j;
    public Object k;
    public Object l;

    public C2538qn(Context context, C2406nk c2406nk, C2023eq c2023eq, VersionInfoParcel versionInfoParcel, Vp vp, C2313ld c2313ld, InterfaceC2529qe interfaceC2529qe, C2475p9 c2475p9, boolean z, BinderC2408nm binderC2408nm, Ek ek, Hk hk) {
        this.b = context;
        this.c = c2406nk;
        this.d = c2023eq;
        this.e = versionInfoParcel;
        this.f = vp;
        this.g = c2313ld;
        this.h = interfaceC2529qe;
        this.i = c2475p9;
        this.a = z;
        this.j = binderC2408nm;
        this.k = ek;
        this.l = hk;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r16v0 */
    /* JADX WARN: Type inference failed for: r16v1 */
    /* JADX WARN: Type inference failed for: r16v6 */
    public void a(com.google.android.material.shape.j jVar, float f, RectF rectF, androidx.webkit.internal.p pVar, Path path) {
        Matrix[] matrixArr;
        Matrix[] matrixArr2;
        com.airbnb.lottie.value.b[] bVarArr;
        int i;
        boolean z;
        float[] fArr;
        float f2;
        boolean z2;
        int i2;
        path.rewind();
        Path path2 = (Path) this.f;
        path2.rewind();
        Path path3 = (Path) this.g;
        path3.rewind();
        path3.addRect(rectF, Path.Direction.CW);
        int i3 = 0;
        while (true) {
            matrixArr = (Matrix[]) this.d;
            matrixArr2 = (Matrix[]) this.c;
            bVarArr = (com.airbnb.lottie.value.b[]) this.b;
            z = 0;
            fArr = (float[]) this.i;
            if (i3 >= 4) {
                break;
            }
            com.google.android.material.shape.c cVar = i3 != 1 ? i3 != 2 ? i3 != 3 ? jVar.f : jVar.e : jVar.h : jVar.g;
            AbstractC3460g4 abstractC3460g4 = i3 != 1 ? i3 != 2 ? i3 != 3 ? jVar.b : jVar.a : jVar.d : jVar.c;
            com.airbnb.lottie.value.b bVar = bVarArr[i3];
            abstractC3460g4.getClass();
            abstractC3460g4.a(bVar, f, cVar.a(rectF));
            int i4 = i3 + 1;
            float f3 = (i4 % 4) * 90;
            matrixArr2[i3].reset();
            PointF pointF = (PointF) this.e;
            if (i3 == 1) {
                i2 = i3;
                pointF.set(rectF.right, rectF.bottom);
            } else if (i3 == 2) {
                i2 = i3;
                pointF.set(rectF.left, rectF.bottom);
            } else if (i3 != 3) {
                i2 = i3;
                pointF.set(rectF.right, rectF.top);
            } else {
                i2 = i3;
                pointF.set(rectF.left, rectF.top);
            }
            matrixArr2[i2].setTranslate(pointF.x, pointF.y);
            matrixArr2[i2].preRotate(f3);
            com.airbnb.lottie.value.b bVar2 = bVarArr[i2];
            fArr[0] = bVar2.b;
            fArr[1] = bVar2.c;
            matrixArr2[i2].mapPoints(fArr);
            matrixArr[i2].reset();
            matrixArr[i2].setTranslate(fArr[0], fArr[1]);
            matrixArr[i2].preRotate(f3);
            i3 = i4;
        }
        int i5 = 0;
        for (i = 4; i5 < i; i = 4) {
            com.airbnb.lottie.value.b bVar3 = bVarArr[i5];
            bVar3.getClass();
            fArr[z] = 0.0f;
            fArr[1] = bVar3.a;
            matrixArr2[i5].mapPoints(fArr);
            if (i5 == 0) {
                path.moveTo(fArr[z], fArr[1]);
            } else {
                path.lineTo(fArr[z], fArr[1]);
            }
            bVarArr[i5].c(matrixArr2[i5], path);
            if (pVar != null) {
                com.airbnb.lottie.value.b bVar4 = bVarArr[i5];
                Matrix matrix = matrixArr2[i5];
                com.google.android.material.shape.g gVar = (com.google.android.material.shape.g) pVar.b;
                f2 = 0.0f;
                BitSet bitSet = gVar.d;
                bVar4.getClass();
                bitSet.set(i5, z);
                bVar4.b(bVar4.e);
                gVar.b[i5] = new com.google.android.material.shape.l(new ArrayList((ArrayList) bVar4.g), new Matrix(matrix));
            } else {
                f2 = 0.0f;
            }
            int i6 = i5 + 1;
            int i7 = i6 % 4;
            com.airbnb.lottie.value.b bVar5 = bVarArr[i5];
            fArr[0] = bVar5.b;
            fArr[1] = bVar5.c;
            matrixArr2[i5].mapPoints(fArr);
            com.airbnb.lottie.value.b bVar6 = bVarArr[i7];
            bVar6.getClass();
            float[] fArr2 = (float[]) this.j;
            fArr2[0] = f2;
            fArr2[1] = bVar6.a;
            matrixArr2[i7].mapPoints(fArr2);
            Matrix[] matrixArr3 = matrixArr2;
            com.airbnb.lottie.value.b[] bVarArr2 = bVarArr;
            float fMax = Math.max(((float) Math.hypot(fArr[0] - fArr2[0], fArr[1] - fArr2[1])) - 0.001f, f2);
            com.airbnb.lottie.value.b bVar7 = bVarArr2[i5];
            fArr[0] = bVar7.b;
            fArr[1] = bVar7.c;
            matrixArr3[i5].mapPoints(fArr);
            float fAbs = (i5 == 1 || i5 == 3) ? Math.abs(rectF.centerX() - fArr[0]) : Math.abs(rectF.centerY() - fArr[1]);
            com.airbnb.lottie.value.b bVar8 = (com.airbnb.lottie.value.b) this.h;
            bVar8.e(DefinitionKt.NO_Float_VALUE, 270.0f, DefinitionKt.NO_Float_VALUE);
            (i5 != 1 ? i5 != 2 ? i5 != 3 ? jVar.j : jVar.i : jVar.l : jVar.k).t(fMax, fAbs, f, bVar8);
            Path path4 = (Path) this.k;
            path4.reset();
            bVar8.c(matrixArr[i5], path4);
            if (this.a && (b(path4, i5) || b(path4, i7))) {
                path4.op(path4, path3, Path.Op.DIFFERENCE);
                fArr[0] = 0.0f;
                fArr[1] = bVar8.a;
                matrixArr[i5].mapPoints(fArr);
                path2.moveTo(fArr[0], fArr[1]);
                bVar8.c(matrixArr[i5], path2);
            } else {
                bVar8.c(matrixArr[i5], path);
            }
            if (pVar != null) {
                Matrix matrix2 = matrixArr[i5];
                com.google.android.material.shape.g gVar2 = (com.google.android.material.shape.g) pVar.b;
                z2 = false;
                gVar2.d.set(i5 + 4, false);
                bVar8.b(bVar8.e);
                gVar2.c[i5] = new com.google.android.material.shape.l(new ArrayList((ArrayList) bVar8.g), new Matrix(matrix2));
            } else {
                z2 = false;
            }
            z = z2;
            bVarArr = bVarArr2;
            matrixArr2 = matrixArr3;
            i5 = i6;
        }
        path.close();
        path2.close();
        if (path2.isEmpty()) {
            return;
        }
        path.op(path2, Path.Op.UNION);
    }

    public boolean b(Path path, int i) {
        Path path2 = (Path) this.l;
        path2.reset();
        ((com.airbnb.lottie.value.b[]) this.b)[i].c(((Matrix[]) this.c)[i], path2);
        RectF rectF = new RectF();
        path.computeBounds(rectF, true);
        path2.computeBounds(rectF, true);
        path.op(path2, Path.Op.INTERSECT);
        path.computeBounds(rectF, true);
        return !rectF.isEmpty() || (rectF.width() > 1.0f && rectF.height() > 1.0f);
    }

    public A9 c() {
        ArrayList arrayList = (ArrayList) this.c;
        if (arrayList.isEmpty()) {
            return A9.a;
        }
        int iC = 0;
        for (int i = 0; i < arrayList.size(); i++) {
            FD fd = (FD) arrayList.get(i);
            fd.d = iC;
            iC += fd.a.o.b.c();
        }
        return new LD(arrayList, (CF) this.l);
    }

    public A9 d(int i, int i2, List list) {
        ArrayList arrayList = (ArrayList) this.c;
        AbstractC1795We.B(i >= 0 && i <= i2 && i2 <= arrayList.size());
        AbstractC1795We.B(list.size() == i2 - i);
        for (int i3 = i; i3 < i2; i3++) {
            ((FD) arrayList.get(i3)).a.p((C2640t3) list.get(i3 - i));
        }
        return c();
    }

    public void e(C2050fG c2050fG) {
        AbstractC1795We.L(!this.a);
        this.k = c2050fG;
        int i = 0;
        while (true) {
            ArrayList arrayList = (ArrayList) this.c;
            if (i >= arrayList.size()) {
                this.a = true;
                return;
            }
            FD fd = (FD) arrayList.get(i);
            o(fd);
            ((HashSet) this.h).add(fd);
            i++;
        }
    }

    public void f(InterfaceC2005eF interfaceC2005eF) {
        IdentityHashMap identityHashMap = (IdentityHashMap) this.d;
        FD fd = (FD) identityHashMap.remove(interfaceC2005eF);
        fd.getClass();
        fd.a.a(interfaceC2005eF);
        fd.c.remove(((ZE) interfaceC2005eF).a);
        if (!identityHashMap.isEmpty()) {
            m();
        }
        n(fd);
    }

    public boolean g() {
        return this.a;
    }

    public A9 h(int i, List list, CF cf) {
        if (!list.isEmpty()) {
            this.l = cf;
            for (int i2 = i; i2 < list.size() + i; i2++) {
                FD fd = (FD) list.get(i2 - i);
                ArrayList arrayList = (ArrayList) this.c;
                if (i2 > 0) {
                    FD fd2 = (FD) arrayList.get(i2 - 1);
                    fd.d = fd2.a.o.b.c() + fd2.d;
                    fd.e = false;
                    fd.c.clear();
                } else {
                    fd.d = 0;
                    fd.e = false;
                    fd.c.clear();
                }
                int iC = fd.a.o.b.c();
                for (int i3 = i2; i3 < arrayList.size(); i3++) {
                    ((FD) arrayList.get(i3)).d += iC;
                }
                arrayList.add(i2, fd);
                ((HashMap) this.e).put(fd.b, fd);
                if (this.a) {
                    o(fd);
                    if (((IdentityHashMap) this.d).isEmpty()) {
                        ((HashSet) this.h).add(fd);
                    } else {
                        ED ed = (ED) ((HashMap) this.g).get(fd);
                        if (ed != null) {
                            ed.a.e(ed.b);
                        }
                    }
                }
            }
        }
        return c();
    }

    public A9 i(int i, int i2, CF cf) {
        boolean z = false;
        if (i >= 0 && i <= i2 && i2 <= ((ArrayList) this.c).size()) {
            z = true;
        }
        AbstractC1795We.B(z);
        this.l = cf;
        p(i, i2);
        return c();
    }

    public A9 j(List list, CF cf) {
        ArrayList arrayList = (ArrayList) this.c;
        p(0, arrayList.size());
        return h(arrayList.size(), list, cf);
    }

    @Override // com.google.android.gms.internal.ads.Ai
    public void k(boolean z, Context context, C2058fh c2058fh) {
        float f;
        C1838af c1838af = (C1838af) AbstractC2025es.Q((C2313ld) this.g);
        try {
            InterfaceC2529qe interfaceC2529qeA = (InterfaceC2529qe) this.h;
            boolean zM0 = interfaceC2529qeA.M0();
            boolean z2 = this.a;
            C2023eq c2023eq = (C2023eq) this.d;
            Vp vp = (Vp) this.f;
            C2475p9 c2475p9 = (C2475p9) this.i;
            if (zM0) {
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.S0)).booleanValue()) {
                    interfaceC2529qeA = ((C2406nk) this.c).a(c2023eq.e, null, null);
                    interfaceC2529qeA.O0("/reward", new C1956d9((C2575ri) c1838af.W.zzb(), 4));
                    C2147hi c2147hi = new C2147hi(12, (byte) 0);
                    ((C2363mk) c1838af.X.zzb()).a(interfaceC2529qeA, true, z2 ? c2475p9 : null, ((Ek) this.k).d);
                    interfaceC2529qeA.L().g = new Km(c2147hi, interfaceC2529qeA);
                    interfaceC2529qeA.L().h = new C2881yn(interfaceC2529qeA, 23);
                    Yp yp = vp.s;
                    interfaceC2529qeA.w0(yp.b, yp.a);
                }
            }
            InterfaceC2529qe interfaceC2529qe = interfaceC2529qeA;
            interfaceC2529qe.I0(true);
            boolean z3 = false;
            boolean zA = z2 ? c2475p9.a(false) : false;
            com.google.android.gms.ads.internal.util.F f2 = com.google.android.gms.ads.internal.j.C.c;
            boolean zH = com.google.android.gms.ads.internal.util.F.h((Context) this.b);
            if (z2) {
                synchronized (c2475p9) {
                    z3 = c2475p9.b;
                }
            }
            boolean z4 = z3;
            if (z2) {
                synchronized (c2475p9) {
                    f = c2475p9.c;
                }
            } else {
                f = DefinitionKt.NO_Float_VALUE;
            }
            zzl zzlVar = new zzl(zA, zH, z4, f, z, vp.O, vp.P);
            if (c2058fh != null) {
                c2058fh.f();
            }
            BinderC2408nm binderC2408nm = null;
            C2919zi c2919zi = (C2919zi) c1838af.V.zzb();
            Yp yp2 = vp.s;
            String str = yp2.b;
            if (vp.b()) {
                binderC2408nm = (BinderC2408nm) this.j;
            }
            assistantMode.utils.studiableMetadata.b.a0(context, new AdOverlayInfoParcel(c2919zi, interfaceC2529qe, vp.Q, (VersionInfoParcel) this.e, vp.B, zzlVar, str, yp2.a, c2023eq.f, c2058fh, binderC2408nm, interfaceC2529qe.w()), true, (Hk) this.l);
        } catch (zzcfn e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
    }

    public A9 l(CF cf) {
        int size = ((ArrayList) this.c).size();
        if (cf.b.length != size) {
            cf = new CF(new Random(cf.a.nextLong())).a(size);
        }
        this.l = cf;
        return c();
    }

    public void m() {
        Iterator it2 = ((HashSet) this.h).iterator();
        while (it2.hasNext()) {
            FD fd = (FD) it2.next();
            if (fd.c.isEmpty()) {
                ED ed = (ED) ((HashMap) this.g).get(fd);
                if (ed != null) {
                    ed.a.e(ed.b);
                }
                it2.remove();
            }
        }
    }

    public void n(FD fd) {
        if (fd.e && fd.c.isEmpty()) {
            ED ed = (ED) ((HashMap) this.g).remove(fd);
            ed.getClass();
            C2908zD c2908zD = ed.b;
            NE ne = ed.a;
            ne.l(c2908zD);
            DD dd = ed.c;
            ne.o(dd);
            ne.n(dd);
            ((HashSet) this.h).remove(fd);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [com.google.android.gms.internal.ads.hF, com.google.android.gms.internal.ads.zD] */
    public void o(FD fd) {
        C1918cF c1918cF = fd.a;
        ?? r1 = new InterfaceC2137hF() { // from class: com.google.android.gms.internal.ads.zD
            @Override // com.google.android.gms.internal.ads.InterfaceC2137hF
            public final void a(NE ne, A9 a9) {
                Bo bo = ((C2436oD) this.a.f).h;
                bo.a.removeMessages(2);
                bo.c(22);
            }
        };
        DD dd = new DD(this, fd);
        ((HashMap) this.g).put(fd, new ED(c1918cF, r1, dd));
        String str = Yo.a;
        Looper looperMyLooper = Looper.myLooper();
        if (looperMyLooper == null) {
            looperMyLooper = Looper.getMainLooper();
        }
        Handler handler = new Handler(looperMyLooper, null);
        C2866yE c2866yE = c1918cF.c;
        c2866yE.getClass();
        c2866yE.b.add(new C2223jF(handler, dd));
        Looper looperMyLooper2 = Looper.myLooper();
        if (looperMyLooper2 == null) {
            looperMyLooper2 = Looper.getMainLooper();
        }
        new Handler(looperMyLooper2, null);
        C2866yE c2866yE2 = c1918cF.d;
        c2866yE2.getClass();
        c2866yE2.b.add(new C2823xE(dd));
        c1918cF.i(r1, (C2050fG) this.k, (C1917cE) this.b);
    }

    public void p(int i, int i2) {
        while (true) {
            i2--;
            if (i2 < i) {
                return;
            }
            ArrayList arrayList = (ArrayList) this.c;
            FD fd = (FD) arrayList.remove(i2);
            ((HashMap) this.e).remove(fd.b);
            int i3 = -fd.a.o.b.c();
            for (int i4 = i2; i4 < arrayList.size(); i4++) {
                ((FD) arrayList.get(i4)).d += i3;
            }
            fd.e = true;
            if (this.a) {
                n(fd);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Ai
    /* renamed from: zza */
    public Vp mo17zza() {
        return (Vp) this.f;
    }

    public C2538qn(C2436oD c2436oD, WD wd, Bo bo, C1917cE c1917cE) {
        this.b = c1917cE;
        this.f = c2436oD;
        this.l = new CF();
        this.d = new IdentityHashMap();
        this.e = new HashMap();
        this.c = new ArrayList();
        this.i = wd;
        this.j = bo;
        this.g = new HashMap();
        this.h = new HashSet();
    }

    public C2538qn() {
        this.b = new com.airbnb.lottie.value.b[4];
        this.c = new Matrix[4];
        this.d = new Matrix[4];
        this.e = new PointF();
        this.f = new Path();
        this.g = new Path();
        this.h = new com.airbnb.lottie.value.b();
        this.i = new float[2];
        this.j = new float[2];
        this.k = new Path();
        this.l = new Path();
        this.a = true;
        for (int i = 0; i < 4; i++) {
            ((com.airbnb.lottie.value.b[]) this.b)[i] = new com.airbnb.lottie.value.b();
            ((Matrix[]) this.c)[i] = new Matrix();
            ((Matrix[]) this.d)[i] = new Matrix();
        }
    }
}
