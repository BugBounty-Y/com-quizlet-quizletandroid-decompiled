package com.google.android.gms.internal.ads;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.os.IBinder;
import android.os.RemoteException;
import android.text.TextUtils;
import androidx.appcompat.view.menu.RunnableC0069f;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.material3.C0591b1;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.internal.overlay.AdOverlayInfoParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.common.internal.InterfaceC1652b;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: com.google.android.gms.internal.ads.lq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2326lq implements Y1, InterfaceC2037f3, InterfaceC1652b, com.google.android.gms.ads.mediation.h, com.google.android.gms.ads.mediation.j, com.google.android.gms.ads.mediation.l, Xh, Gq, Ai, Ep {
    public static C2326lq e;
    public static final C2426o3 f;
    public static final C2426o3 g;
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;

    static {
        long j = -9223372036854775807L;
        f = new C2426o3(2, j);
        g = new C2426o3(3, j);
    }

    public /* synthetic */ C2326lq(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    public static String r(Context context) throws IOException {
        File file = new File(context.getPackageResourcePath());
        if (!file.exists() || !file.canRead()) {
            return "";
        }
        try {
            FileInputStream fileInputStream = new FileInputStream(file);
            try {
                byte[] bArr = new byte[16384];
                MessageDigest messageDigest = MessageDigest.getInstance("SHA256");
                for (int i = fileInputStream.read(bArr); i != -1; i = fileInputStream.read(bArr)) {
                    messageDigest.update(bArr, 0, i);
                }
                Tu tuD = Tu.d.d();
                byte[] bArrDigest = messageDigest.digest();
                String strG = tuD.g(bArrDigest.length, bArrDigest);
                fileInputStream.close();
                return strG;
            } catch (Throwable th) {
                try {
                    fileInputStream.close();
                } catch (Throwable th2) {
                    th.addSuppressed(th2);
                }
                throw th;
            }
        } catch (IOException | UnsupportedOperationException | NoSuchAlgorithmException unused) {
            return "";
        }
    }

    public static C2326lq s(Context context) {
        synchronized (C2326lq.class) {
            try {
                C2326lq c2326lq = e;
                if (c2326lq != null) {
                    return c2326lq;
                }
                Context applicationContext = context.getApplicationContext();
                long jLongValue = ((Long) X7.b.o()).longValue();
                com.google.android.gms.ads.internal.client.Y yAsInterface = null;
                if (jLongValue > 0 && jLongValue <= 251815200) {
                    try {
                        yAsInterface = com.google.android.gms.ads.internal.client.X.asInterface((IBinder) applicationContext.getClassLoader().loadClass("com.google.android.gms.ads.internal.client.LiteSdkInfo").getConstructor(Context.class).newInstance(applicationContext));
                    } catch (ClassCastException | ClassNotFoundException | IllegalAccessException | InstantiationException | NoSuchMethodException | InvocationTargetException e2) {
                        com.google.android.gms.ads.internal.util.client.i.f("Failed to retrieve lite SDK info.", e2);
                    }
                }
                C2326lq c2326lq2 = new C2326lq(applicationContext, yAsInterface);
                e = c2326lq2;
                return c2326lq2;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static final C2326lq w(AbstractC2547qw abstractC2547qw) throws GeneralSecurityException {
        int i;
        int i2;
        char c = 1;
        com.bumptech.glide.manager.p pVar = new com.bumptech.glide.manager.p(10);
        C2375mw c2375mw = new C2375mw(abstractC2547qw);
        C1 c1 = C1.k;
        c2375mw.c = c1;
        c2375mw.a = true;
        ArrayList arrayList = (ArrayList) pVar.b;
        Iterator it2 = arrayList.iterator();
        while (true) {
            i = 0;
            if (!it2.hasNext()) {
                break;
            }
            ((C2375mw) it2.next()).a = false;
        }
        arrayList.add(c2375mw);
        if (pVar.a) {
            throw new GeneralSecurityException("KeysetHandle.Builder#build must only be called once");
        }
        pVar.a = true;
        Iz izY = Lz.y();
        ArrayList arrayList2 = new ArrayList(arrayList.size());
        int i3 = 0;
        while (i3 < arrayList.size() - 1) {
            int i4 = i3 + 1;
            if (((C2375mw) arrayList.get(i3)).c == c1 && ((C2375mw) arrayList.get(i4)).c != c1) {
                throw new GeneralSecurityException("Entries with 'withRandomId()' may only be followed by other entries with 'withRandomId()'.");
            }
            i3 = i4;
        }
        HashSet hashSet = new HashSet();
        Iterator it3 = arrayList.iterator();
        Integer num = null;
        while (it3.hasNext()) {
            C2375mw c2375mw2 = (C2375mw) it3.next();
            c2375mw2.getClass();
            C1 c12 = c2375mw2.c;
            if (c12 == null) {
                throw new GeneralSecurityException("No ID was set (with withFixedId or withRandomId)");
            }
            int i5 = 3;
            if (c12 == c1) {
                i2 = i;
                while (true) {
                    if (i2 != 0 && !hashSet.contains(Integer.valueOf(i2))) {
                        break;
                    }
                    int i6 = AbstractC2677ty.a;
                    i2 = i;
                    while (i2 == 0) {
                        byte[] bArr = new byte[4];
                        ((SecureRandom) AbstractC2463oy.a.get()).nextBytes(bArr);
                        i2 = (bArr[3] & 255) | ((bArr[2] & 255) << 8) | ((bArr[i] & 255) << 24) | ((bArr[c] & 255) << 16);
                        i = 0;
                    }
                }
            } else {
                i2 = 0;
            }
            Integer numValueOf = Integer.valueOf(i2);
            if (hashSet.contains(numValueOf)) {
                throw new GeneralSecurityException(AbstractC0147y.c(i2, "Id ", " is used twice in the keyset"));
            }
            hashSet.add(numValueOf);
            AbstractC2547qw abstractC2547qw2 = c2375mw2.b;
            AbstractC2025es abstractC2025esA = Qx.b.a(abstractC2547qw2, c != abstractC2547qw2.a() ? null : numValueOf);
            C2332lw c2332lw = C2332lw.c;
            C2418nw c2418nw = new C2418nw(abstractC2025esA, c2332lw, i2, c2375mw2.a);
            C2377my c2377my = (C2377my) Xx.b.c(abstractC2025esA);
            Integer num2 = c2377my.f;
            if (num2 != null && num2.intValue() != i2) {
                throw new GeneralSecurityException("Wrong ID set for key with ID requirement");
            }
            if (!c2332lw.equals(c2332lw)) {
                if (C2332lw.d.equals(c2332lw)) {
                    i5 = 4;
                } else {
                    if (!C2332lw.e.equals(c2332lw)) {
                        throw new IllegalStateException("Unknown key status");
                    }
                    i5 = 5;
                }
            }
            Jz jzY = Kz.y();
            Dz dzW = Ez.w();
            dzW.e();
            C1 c13 = c1;
            Ez.C((Ez) dzW.b, c2377my.a);
            dzW.e();
            Ez.D((Ez) dzW.b, c2377my.c);
            dzW.e();
            Ez.B((Ez) dzW.b, c2377my.d);
            jzY.e();
            Kz.A((Kz) jzY.b, (Ez) dzW.c());
            jzY.e();
            Kz.F((Kz) jzY.b, i5);
            jzY.e();
            ((Kz) jzY.b).zzf = i2;
            jzY.e();
            ((Kz) jzY.b).zzg = c2377my.e.a();
            Kz kz = (Kz) jzY.c();
            izY.e();
            Lz.C((Lz) izY.b, kz);
            if (c2375mw2.a) {
                if (num != null) {
                    throw new GeneralSecurityException("Two primaries were set");
                }
                num = numValueOf;
            }
            arrayList2.add(c2418nw);
            c1 = c13;
            c = 1;
            i = 0;
        }
        if (num == null) {
            throw new GeneralSecurityException("No primary was set");
        }
        int iIntValue = num.intValue();
        izY.e();
        ((Lz) izY.b).zzc = iIntValue;
        Lz lz = (Lz) izY.c();
        if (lz.w() > 0) {
            return new C2326lq(lz, arrayList2, (Px) pVar.c);
        }
        throw new GeneralSecurityException("empty keyset");
    }

    public Nv A(zzbvl zzbvlVar, Ol ol, Ol ol2, Fv fv) {
        String str = zzbvlVar.d;
        com.google.android.gms.ads.internal.util.F f2 = com.google.android.gms.ads.internal.j.C.c;
        boolean zD = com.google.android.gms.ads.internal.util.F.d(str);
        C2227jd c2227jd = (C2227jd) this.b;
        return AbstractC2025es.A(AbstractC2025es.N(AbstractC2025es.N(Nv.t(zD ? AbstractC2025es.C(new zzdyq(1)) : AbstractC2025es.A(ol.d(zzbvlVar), ExecutionException.class, new C2487pf(6), c2227jd)), new C2487pf(5), c2227jd), fv, c2227jd), zzdyq.class, new com.google.android.gms.ads.internal.c(this, ol2, zzbvlVar, fv, 4), c2227jd);
    }

    public Object B(C2883yp c2883yp) throws GeneralSecurityException {
        boolean z = false;
        if (c2883yp == null) {
            throw new GeneralSecurityException("Currently only subclasses of InternalConfiguration are accepted");
        }
        int i = AbstractC2632sw.a;
        Lz lz = (Lz) this.b;
        int iX = lz.x();
        int i2 = 0;
        boolean z2 = false;
        boolean z3 = true;
        for (Kz kz : lz.B()) {
            if (kz.E() == 3) {
                if (!kz.D()) {
                    throw new GeneralSecurityException(String.format("key %d has no key data", Integer.valueOf(kz.w())));
                }
                if (kz.z() == Yz.UNKNOWN_PREFIX) {
                    throw new GeneralSecurityException(String.format("key %d has unknown prefix", Integer.valueOf(kz.w())));
                }
                if (kz.E() == 2) {
                    throw new GeneralSecurityException(String.format("key %d has unknown status", Integer.valueOf(kz.w())));
                }
                if (kz.w() == iX) {
                    if (z2) {
                        throw new GeneralSecurityException("keyset contains multiple primary keys");
                    }
                    z2 = true;
                }
                z3 &= kz.x().x() == 4;
                i2++;
            }
        }
        if (i2 == 0) {
            throw new GeneralSecurityException("keyset must contain at least one ENABLED key");
        }
        if (!z2 && !z3) {
            throw new GeneralSecurityException("keyset doesn't contain a valid primary key");
        }
        int i3 = 0;
        while (true) {
            List list = (List) this.c;
            if (i3 >= list.size()) {
                C2291ky c2291ky = (C2291ky) c2883yp.b;
                HashMap map = c2291ky.b;
                if (!map.containsKey(InterfaceC2289kw.class)) {
                    throw new GeneralSecurityException("No wrapper found for ".concat(InterfaceC2289kw.class.toString()));
                }
                InterfaceC2334ly interfaceC2334ly = (InterfaceC2334ly) map.get(InterfaceC2289kw.class);
                return interfaceC2334ly.a(this, (Px) this.d, new Fp(c2291ky, z, interfaceC2334ly, 6));
            }
            if (list.get(i3) == null) {
                throw new GeneralSecurityException("Key parsing of key with index " + i3 + " and type_url " + lz.z(i3).x().A() + " failed, unable to get primitive");
            }
            i3++;
        }
    }

    @Override // com.google.android.gms.internal.ads.Y1
    public long F(int i) {
        AbstractC1795We.B(i >= 0);
        long[] jArr = (long[]) this.d;
        AbstractC1795We.B(i < jArr.length);
        return jArr[i];
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public void V(int i) {
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public void X() {
        com.bumptech.glide.manager.p pVar = (com.bumptech.glide.manager.p) this.d;
        synchronized (pVar.c) {
            try {
                if (pVar.a) {
                    return;
                }
                pVar.a = true;
                C2172i6 c2172i6 = (C2172i6) pVar.b;
                if (c2172i6 == null) {
                    return;
                }
                C2227jd c2227jd = AbstractC2270kd.a;
                zzbbf zzbbfVar = (zzbbf) this.b;
                C2257k6 c2257k6 = (C2257k6) this.c;
                c2257k6.a.a(new Qv(c2257k6, false, c2227jd.a(new RunnableC0069f(9, this, c2172i6, zzbbfVar, c2257k6, false)), 5), AbstractC2270kd.g);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void a() {
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        com.google.android.gms.ads.internal.util.client.i.d("Adapter called onAdFailedToLoad with error 0.");
        try {
            ((InterfaceC1671Ca) this.b).e(0);
        } catch (RemoteException e2) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e2);
        }
    }

    @Override // com.google.android.gms.internal.ads.Gq
    public Object b(Object obj) {
        C2107gm c2107gm = (C2107gm) this.b;
        c2107gm.getClass();
        c2107gm.b.execute(new C((SQLiteDatabase) obj, (String) this.d, (com.google.android.gms.ads.internal.util.client.k) this.c, 7));
        return null;
    }

    public void c(com.google.android.gms.ads.b bVar) {
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        com.google.android.gms.ads.internal.util.client.i.d("Adapter called onAdFailedToLoad with error. ErrorCode: " + bVar.a + ". ErrorMessage: " + bVar.b + ". ErrorDomain: " + bVar.c);
        try {
            ((InterfaceC1671Ca) this.b).S0(bVar.a());
        } catch (RemoteException e2) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e2);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2037f3
    public void d(Kn kn) {
        long jD;
        long j;
        AbstractC1795We.p((Eo) this.c);
        String str = Yo.a;
        Eo eo = (Eo) this.c;
        synchronized (eo) {
            try {
                long j2 = eo.c;
                jD = j2 != -9223372036854775807L ? j2 + eo.b : eo.d();
            } finally {
            }
        }
        Eo eo2 = (Eo) this.c;
        synchronized (eo2) {
            j = eo2.b;
        }
        if (jD == -9223372036854775807L || j == -9223372036854775807L) {
            return;
        }
        C1832aG c1832aG = (C1832aG) this.b;
        if (j != c1832aG.r) {
            EF ef = new EF(c1832aG);
            ef.q = j;
            C1832aG c1832aG2 = new C1832aG(ef);
            this.b = c1832aG2;
            ((InterfaceC2380n0) this.d).a(c1832aG2);
        }
        int iS = kn.s();
        ((InterfaceC2380n0) this.d).e(iS, kn);
        ((InterfaceC2380n0) this.d).f(jD, 1, iS, 0, null);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2037f3
    public void e(Eo eo, W w, C0591b1 c0591b1) {
        this.c = eo;
        c0591b1.b();
        c0591b1.c();
        InterfaceC2380n0 interfaceC2380n0Q = w.q(c0591b1.c, 5);
        this.d = interfaceC2380n0Q;
        interfaceC2380n0Q.a((C1832aG) this.b);
    }

    public void f(com.google.android.gms.ads.b bVar) {
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        com.google.android.gms.ads.internal.util.client.i.d("Adapter called onAdFailedToLoad with error. ErrorCode: " + bVar.a + ". ErrorMessage: " + bVar.b + ". ErrorDomain: " + bVar.c);
        try {
            ((InterfaceC1671Ca) this.b).S0(bVar.a());
        } catch (RemoteException e2) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e2);
        }
    }

    public void g(com.google.android.gms.ads.b bVar) {
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        com.google.android.gms.ads.internal.util.client.i.d("Adapter called onAdFailedToLoad with error. ErrorCode: " + bVar.a + ". ErrorMessage: " + bVar.b + ". ErrorDomain: " + bVar.c);
        try {
            ((InterfaceC1671Ca) this.b).S0(bVar.a());
        } catch (RemoteException e2) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e2);
        }
    }

    public ArrayList h() {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = ((ArrayList) this.c).iterator();
        while (it2.hasNext()) {
            String str = (String) com.google.android.gms.ads.internal.client.r.d.c.a((C2601s7) it2.next());
            if (!TextUtils.isEmpty(str)) {
                arrayList.add(str);
            }
        }
        ArrayList arrayList2 = new ArrayList();
        AbstractC1972di.v(arrayList2, new I3("gad:dynamite_module:experiment_id", 4, ""));
        AbstractC1972di.v(arrayList2, AbstractC1972di.e);
        AbstractC1972di.v(arrayList2, AbstractC1972di.f);
        AbstractC1972di.v(arrayList2, AbstractC1972di.g);
        AbstractC1972di.v(arrayList2, AbstractC1972di.h);
        AbstractC1972di.v(arrayList2, AbstractC1972di.i);
        AbstractC1972di.v(arrayList2, AbstractC1972di.y);
        AbstractC1972di.v(arrayList2, AbstractC1972di.j);
        AbstractC1972di.v(arrayList2, AbstractC1972di.q);
        AbstractC1972di.v(arrayList2, AbstractC1972di.r);
        AbstractC1972di.v(arrayList2, AbstractC1972di.s);
        AbstractC1972di.v(arrayList2, AbstractC1972di.t);
        AbstractC1972di.v(arrayList2, AbstractC1972di.u);
        AbstractC1972di.v(arrayList2, AbstractC1972di.v);
        AbstractC1972di.v(arrayList2, AbstractC1972di.w);
        AbstractC1972di.v(arrayList2, AbstractC1972di.x);
        AbstractC1972di.v(arrayList2, AbstractC1972di.k);
        AbstractC1972di.v(arrayList2, AbstractC1972di.l);
        AbstractC1972di.v(arrayList2, AbstractC1972di.m);
        AbstractC1972di.v(arrayList2, AbstractC1972di.n);
        AbstractC1972di.v(arrayList2, AbstractC1972di.o);
        AbstractC1972di.v(arrayList2, AbstractC1972di.p);
        arrayList.addAll(arrayList2);
        return arrayList;
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0059  */
    /* JADX WARN: Removed duplicated region for block: B:13:0x005c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void i(com.google.android.gms.internal.ads.Xp r3, com.google.android.gms.internal.ads.Vp r4, int r5, com.google.android.gms.internal.ads.zzedj r6, long r7) {
        /*
            r2 = this;
            java.lang.Object r0 = r2.d
            com.google.android.gms.internal.ads.Hk r0 = (com.google.android.gms.internal.ads.Hk) r0
            com.google.android.gms.internal.ads.Fi r0 = r0.a()
            java.lang.String r1 = "gqi"
            java.lang.String r3 = r3.b
            r0.o(r1, r3)
            r0.p(r4)
            java.lang.String r3 = "action"
            java.lang.String r1 = "adapter_status"
            r0.o(r3, r1)
            java.lang.String r3 = "adapter_l"
            java.lang.String r7 = java.lang.String.valueOf(r7)
            r0.o(r3, r7)
            java.lang.String r3 = "sc"
            java.lang.String r5 = java.lang.Integer.toString(r5)
            r0.o(r3, r5)
            r3 = 0
            if (r6 == 0) goto L61
            com.google.android.gms.ads.internal.client.zze r5 = r6.b
            int r5 = r5.a
            java.lang.String r5 = java.lang.Integer.toString(r5)
            java.lang.String r7 = "arec"
            r0.o(r7, r5)
            java.lang.String r5 = r6.getMessage()
            java.lang.Object r6 = r2.b
            com.google.android.gms.internal.ads.kq r6 = (com.google.android.gms.internal.ads.C2283kq) r6
            java.util.regex.Pattern r6 = r6.a
            if (r6 == 0) goto L59
            if (r5 != 0) goto L4a
            goto L59
        L4a:
            java.util.regex.Matcher r5 = r6.matcher(r5)
            boolean r6 = r5.find()
            if (r6 == 0) goto L59
            java.lang.String r5 = r5.group()
            goto L5a
        L59:
            r5 = r3
        L5a:
            if (r5 == 0) goto L61
            java.lang.String r6 = "areec"
            r0.o(r6, r5)
        L61:
            java.util.List r4 = r4.t
            java.util.Iterator r4 = r4.iterator()
        L67:
            boolean r5 = r4.hasNext()
            if (r5 == 0) goto L7e
            java.lang.Object r5 = r4.next()
            java.lang.String r5 = (java.lang.String) r5
            java.lang.Object r6 = r2.c
            com.google.android.gms.internal.ads.sk r6 = (com.google.android.gms.internal.ads.C2620sk) r6
            com.google.android.gms.internal.ads.rk r5 = r6.a(r5)
            if (r5 == 0) goto L67
            r3 = r5
        L7e:
            if (r3 == 0) goto La1
            java.lang.String r4 = "ancn"
            java.lang.String r5 = r3.a
            r0.o(r4, r5)
            com.google.android.gms.internal.ads.zzbrz r4 = r3.b
            if (r4 == 0) goto L94
            java.lang.String r5 = "adapter_v"
            java.lang.String r4 = r4.toString()
            r0.o(r5, r4)
        L94:
            com.google.android.gms.internal.ads.zzbrz r3 = r3.c
            if (r3 == 0) goto La1
            java.lang.String r4 = "adapter_sv"
            java.lang.String r3 = r3.toString()
            r0.o(r4, r3)
        La1:
            r0.x()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2326lq.i(com.google.android.gms.internal.ads.Xp, com.google.android.gms.internal.ads.Vp, int, com.google.android.gms.internal.ads.zzedj, long):void");
    }

    @Override // com.google.android.gms.internal.ads.Ep
    public /* bridge */ /* synthetic */ Object j() {
        return null;
    }

    @Override // com.google.android.gms.internal.ads.Ai
    public void k(boolean z, Context context, C2058fh c2058fh) throws zzdgh {
        zzfcw zzfcwVar;
        switch (this.a) {
            case 19:
                try {
                    assistantMode.utils.studiableMetadata.b bVar = com.google.android.gms.ads.internal.j.C.b;
                    assistantMode.utils.studiableMetadata.b.a0(context, (AdOverlayInfoParcel) ((C2313ld) this.b).a.get(), true, (Hk) ((Qm) this.d).f);
                    return;
                } catch (Exception unused) {
                    return;
                }
            default:
                try {
                    C2369mq c2369mq = (C2369mq) ((C2880ym) this.b).b;
                    c2369mq.b(z);
                    int i = ((VersionInfoParcel) ((Om) this.d).d).c;
                    int iIntValue = ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.N0)).intValue();
                    InterfaceC2911za interfaceC2911za = c2369mq.a;
                    if (i < iIntValue) {
                        try {
                            interfaceC2911za.h0();
                            return;
                        } finally {
                        }
                    } else {
                        try {
                            interfaceC2911za.U3(new com.google.android.gms.dynamic.b(context));
                            return;
                        } finally {
                        }
                    }
                } catch (zzfcw e2) {
                    com.google.android.gms.ads.internal.util.client.i.g("Cannot show interstitial.");
                    throw new zzdgh(e2.getCause());
                }
                com.google.android.gms.ads.internal.util.client.i.g("Cannot show interstitial.");
                throw new zzdgh(e2.getCause());
        }
    }

    public Xp l() {
        return (Xp) ((C1849aq) this.b).b.b;
    }

    public C2418nw m(int i) {
        List list = (List) this.c;
        if (i < 0 || i >= list.size()) {
            throw new IndexOutOfBoundsException(androidx.compose.animation.d0.p("Invalid index ", i, " for keyset of size ", list.size()));
        }
        if (list.get(i) != null) {
            return (C2418nw) list.get(i);
        }
        throw new IllegalStateException(AbstractC0147y.c(i, "Keyset-Entry at position ", " has wrong status or key parsing failed"));
    }

    public com.google.common.util.concurrent.e n(Fp fp, Dp dp, Qg qg) {
        com.google.common.util.concurrent.e eVarE;
        com.google.common.util.concurrent.e eVarX;
        C2326lq c2326lq = (C2326lq) this.b;
        Xv xv = (Xv) this.c;
        C2326lq c2326lq2 = new C2326lq(c2326lq, qg, xv);
        Ap ap = (Ap) c2326lq2.d;
        if (ap == null) {
            if (((Boolean) AbstractC1998e8.a.o()).booleanValue()) {
                C2831xg c2831xgZzb = qg.zzb();
                Jq jq = Jq.GET_CACHE_KEY;
                Iq iqB = c2831xgZzb.c.a(c2831xgZzb.i.w(), jq).m(new C2439oa(3, c2831xgZzb, (zzfej) c2326lq.c)).b();
                iqB.a(new Qv(0, iqB, new S4(c2831xgZzb, 11)), c2831xgZzb.j);
                eVarX = AbstractC2025es.x(AbstractC2025es.L(Nv.t(iqB), new C2926zp(c2326lq2, 1), xv), zzdyq.class, new C2926zp(c2326lq2, 0), xv);
            } else {
                Ap ap2 = new Ap(null, c2326lq2.x());
                c2326lq2.d = ap2;
                eVarX = AbstractC2025es.E(ap2);
            }
            eVarE = AbstractC2025es.L(eVarX, new C2853y1(16), xv);
        } else {
            eVarE = AbstractC2025es.E(ap);
        }
        return AbstractC2025es.x(AbstractC2025es.N(Nv.t(eVarE), new C2439oa(13, this, qg), xv), Exception.class, new C2853y1(15), xv);
    }

    public ArrayList o() {
        ArrayList arrayListH = h();
        Iterator it2 = ((ArrayList) this.d).iterator();
        while (it2.hasNext()) {
            String str = (String) com.google.android.gms.ads.internal.client.r.d.c.a((C2601s7) it2.next());
            if (!TextUtils.isEmpty(str)) {
                arrayListH.add(str);
            }
        }
        ArrayList arrayList = new ArrayList();
        AbstractC1972di.v(arrayList, AbstractC2096gb.k);
        arrayListH.addAll(arrayList);
        return arrayListH;
    }

    public C2418nw p() {
        for (C2418nw c2418nw : (List) this.c) {
            if (c2418nw != null && c2418nw.d) {
                if (c2418nw.b == C2332lw.c) {
                    return c2418nw;
                }
                throw new IllegalStateException("Keyset has primary which isn't enabled");
            }
        }
        throw new IllegalStateException("Keyset has no valid primary");
    }

    @Override // com.google.android.gms.internal.ads.Ep
    public /* bridge */ /* synthetic */ com.google.common.util.concurrent.e q(Fp fp, Dp dp) {
        return n(fp, dp, null);
    }

    public synchronized void t(zzm zzmVar, int i) {
        this.d = null;
        Sn sn = new Sn(i);
        S4 s4 = new S4(this, 23);
        ((C2084g6) this.b).g(zzmVar, (String) this.c, sn, s4);
    }

    public String toString() {
        switch (this.a) {
            case 28:
                StringBuilder sb = new StringBuilder(32);
                sb.append((String) this.b);
                sb.append('{');
                Fp fp = (Fp) ((Fp) this.c).c;
                String str = "";
                while (fp != null) {
                    Object obj = fp.b;
                    sb.append(str);
                    if (obj == null || !obj.getClass().isArray()) {
                        sb.append(obj);
                    } else {
                        sb.append((CharSequence) Arrays.deepToString(new Object[]{obj}), 1, r2.length() - 1);
                    }
                    fp = (Fp) fp.c;
                    str = ", ";
                }
                sb.append('}');
                return sb.toString();
            case 29:
                int i = AbstractC2632sw.a;
                Mz mzW = Pz.w();
                Lz lz = (Lz) this.b;
                int iX = lz.x();
                mzW.e();
                ((Pz) mzW.b).zzc = iX;
                for (Kz kz : lz.B()) {
                    Nz nzW = Oz.w();
                    String strA = kz.x().A();
                    nzW.e();
                    Oz.z((Oz) nzW.b, strA);
                    int iE = kz.E();
                    nzW.e();
                    Oz.A((Oz) nzW.b, iE);
                    Yz yzZ = kz.z();
                    nzW.e();
                    ((Oz) nzW.b).zzf = yzZ.a();
                    int iW = kz.w();
                    nzW.e();
                    ((Oz) nzW.b).zze = iW;
                    Oz oz = (Oz) nzW.c();
                    mzW.e();
                    Pz.x((Pz) mzW.b, oz);
                }
                return ((Pz) mzW.c()).toString();
            default:
                return super.toString();
        }
    }

    public void u(W w, C0591b1 c0591b1) {
        int i = 0;
        while (true) {
            InterfaceC2380n0[] interfaceC2380n0Arr = (InterfaceC2380n0[]) this.c;
            if (i >= interfaceC2380n0Arr.length) {
                return;
            }
            c0591b1.b();
            c0591b1.c();
            InterfaceC2380n0 interfaceC2380n0Q = w.q(c0591b1.c, 3);
            C1832aG c1832aG = (C1832aG) ((List) this.b).get(i);
            String str = c1832aG.m;
            boolean z = true;
            if (!"application/cea-608".equals(str) && !"application/cea-708".equals(str)) {
                z = false;
            }
            AbstractC1795We.G(z, "Invalid closed caption MIME type provided: ".concat(String.valueOf(str)));
            String str2 = c1832aG.a;
            if (str2 == null) {
                c0591b1.c();
                str2 = (String) c0591b1.e;
            }
            EF ef = new EF();
            ef.a = str2;
            ef.a("video/mp2t");
            ef.d(str);
            ef.e = c1832aG.e;
            ef.d = c1832aG.d;
            ef.G = c1832aG.H;
            ef.o = c1832aG.p;
            interfaceC2380n0Q.a(new C1832aG(ef));
            interfaceC2380n0Arr[i] = interfaceC2380n0Q;
            i++;
        }
    }

    public synchronized void v(InterfaceC2798wq interfaceC2798wq, C2755vq c2755vq) {
        try {
            ConcurrentHashMap concurrentHashMap = (ConcurrentHashMap) this.b;
            C2583rq c2583rq = (C2583rq) concurrentHashMap.get(interfaceC2798wq);
            com.google.android.gms.ads.internal.j.C.k.getClass();
            c2755vq.d = System.currentTimeMillis();
            if (c2583rq == null) {
                zzfej zzfejVar = (zzfej) this.c;
                C2583rq c2583rq2 = new C2583rq(zzfejVar.e, zzfejVar.f * 1000);
                if (concurrentHashMap.size() == zzfejVar.d) {
                    int i = zzfejVar.j;
                    int i2 = i - 1;
                    InterfaceC2798wq interfaceC2798wq2 = null;
                    if (i == 0) {
                        throw null;
                    }
                    long j = Long.MAX_VALUE;
                    if (i2 == 0) {
                        for (Map.Entry entry : concurrentHashMap.entrySet()) {
                            if (((C2583rq) entry.getValue()).d.a < j) {
                                j = ((C2583rq) entry.getValue()).d.a;
                                interfaceC2798wq2 = (InterfaceC2798wq) entry.getKey();
                            }
                        }
                        if (interfaceC2798wq2 != null) {
                            concurrentHashMap.remove(interfaceC2798wq2);
                        }
                    } else if (i2 == 1) {
                        for (Map.Entry entry2 : concurrentHashMap.entrySet()) {
                            if (((C2583rq) entry2.getValue()).d.c < j) {
                                j = ((C2583rq) entry2.getValue()).d.c;
                                interfaceC2798wq2 = (InterfaceC2798wq) entry2.getKey();
                            }
                        }
                        if (interfaceC2798wq2 != null) {
                            concurrentHashMap.remove(interfaceC2798wq2);
                        }
                    } else if (i2 == 2) {
                        int i3 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
                        for (Map.Entry entry3 : concurrentHashMap.entrySet()) {
                            if (((C2583rq) entry3.getValue()).d.d < i3) {
                                i3 = ((C2583rq) entry3.getValue()).d.d;
                                interfaceC2798wq2 = (InterfaceC2798wq) entry3.getKey();
                            }
                        }
                        if (interfaceC2798wq2 != null) {
                            concurrentHashMap.remove(interfaceC2798wq2);
                        }
                    }
                    C2669tq c2669tq = (C2669tq) this.d;
                    c2669tq.c++;
                    c2669tq.a.b = true;
                }
                concurrentHashMap.put(interfaceC2798wq, c2583rq2);
                C2669tq c2669tq2 = (C2669tq) this.d;
                c2669tq2.b++;
                c2669tq2.a.a = true;
                c2583rq = c2583rq2;
            }
            Eq eq = c2583rq.d;
            eq.getClass();
            com.google.android.gms.ads.internal.j.C.k.getClass();
            eq.c = System.currentTimeMillis();
            eq.d++;
            c2583rq.a();
            LinkedList linkedList = c2583rq.a;
            if (linkedList.size() != c2583rq.b) {
                linkedList.add(c2755vq);
            }
            C2669tq c2669tq3 = (C2669tq) this.d;
            c2669tq3.f++;
            C2626sq c2626sq = c2669tq3.a;
            C2626sq c2626sqClone = c2626sq.clone();
            c2626sq.a = false;
            c2626sq.b = false;
            Cq cq = c2583rq.d.b;
            Cq cqClone = cq.clone();
            cq.a = false;
            cq.b = 0;
            O6 o6W = T6.w();
            M6 m6Z = N6.z();
            m6Z.e();
            N6.w((N6) m6Z.b);
            R6 r6Z = S6.z();
            boolean z = c2626sqClone.a;
            r6Z.e();
            S6.w((S6) r6Z.b, z);
            boolean z2 = c2626sqClone.b;
            r6Z.e();
            S6.x((S6) r6Z.b, z2);
            int i4 = cqClone.b;
            r6Z.e();
            S6.y((S6) r6Z.b, i4);
            m6Z.e();
            N6.y((N6) m6Z.b, (S6) r6Z.c());
            o6W.e();
            T6.x((T6) o6W.b, (N6) m6Z.c());
            c2755vq.a.zzb().f.T0((T6) o6W.c());
            y();
        } catch (Throwable th) {
            throw th;
        }
    }

    public C2841xq x() {
        C2023eq c2023eqF = ((Qg) this.c).f();
        zzfej zzfejVar = (zzfej) ((C2326lq) this.b).c;
        C1879bc c1879bcA = new C1835ac(zzfejVar.a).a();
        return new C2841xq(c2023eqF.d, c2023eqF.f, c1879bcA.j, zzfejVar.g, c2023eqF.j);
    }

    public void y() {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.m6)).booleanValue()) {
            StringBuilder sb = new StringBuilder();
            zzfej zzfejVar = (zzfej) this.c;
            sb.append(zzfejVar.c);
            sb.append(" PoolCollection");
            StringBuilder sb2 = new StringBuilder("\n\tPool does not exist: ");
            C2669tq c2669tq = (C2669tq) this.d;
            sb2.append(c2669tq.d);
            sb2.append("\n\tNew pools created: ");
            sb2.append(c2669tq.b);
            sb2.append("\n\tPools removed: ");
            sb2.append(c2669tq.c);
            sb2.append("\n\tEntries added: ");
            sb2.append(c2669tq.f);
            sb2.append("\n\tNo entries retrieved: ");
            sb2.append(c2669tq.e);
            sb2.append("\n");
            sb.append(sb2.toString());
            int i = 0;
            for (Map.Entry entry : ((ConcurrentHashMap) this.b).entrySet()) {
                i++;
                sb.append(i);
                sb.append(". ");
                sb.append(entry.getValue());
                sb.append("#");
                sb.append(((InterfaceC2798wq) entry.getKey()).hashCode());
                sb.append("    ");
                int i2 = 0;
                while (true) {
                    C2583rq c2583rq = (C2583rq) entry.getValue();
                    c2583rq.a();
                    if (i2 >= c2583rq.a.size()) {
                        break;
                    }
                    sb.append("[O]");
                    i2++;
                }
                C2583rq c2583rq2 = (C2583rq) entry.getValue();
                c2583rq2.a();
                for (int size = c2583rq2.a.size(); size < zzfejVar.e; size++) {
                    sb.append("[ ]");
                }
                sb.append("\n");
                C2583rq c2583rq3 = (C2583rq) entry.getValue();
                StringBuilder sb3 = new StringBuilder("Created: ");
                Eq eq = c2583rq3.d;
                sb3.append(eq.a);
                sb3.append(" Last accessed: ");
                sb3.append(eq.c);
                sb3.append(" Accesses: ");
                sb3.append(eq.d);
                sb3.append("\nEntries retrieved: Valid: ");
                sb3.append(eq.e);
                sb3.append(" Stale: ");
                sb3.append(eq.f);
                sb.append(sb3.toString());
                sb.append("\n");
            }
            while (i < zzfejVar.d) {
                i++;
                sb.append(i);
                sb.append(".\n");
            }
            com.google.android.gms.ads.internal.util.client.i.d(sb.toString());
        }
    }

    public void z(InterfaceC2825xa interfaceC2825xa) {
        InterfaceC2825xa adapterCreator;
        boolean zBooleanValue = ((Boolean) X7.a.o()).booleanValue();
        AtomicReference atomicReference = (AtomicReference) this.d;
        if (!zBooleanValue) {
            while (!atomicReference.compareAndSet(null, interfaceC2825xa)) {
                if (atomicReference.get() != null && atomicReference.get() != null) {
                    return;
                }
            }
            return;
        }
        com.google.android.gms.ads.internal.client.Y y = (com.google.android.gms.ads.internal.client.Y) this.c;
        if (y == null) {
            adapterCreator = null;
        } else {
            try {
                adapterCreator = y.getAdapterCreator();
            } catch (RemoteException unused) {
            }
        }
        if (adapterCreator == null) {
            adapterCreator = interfaceC2825xa;
        }
        while (!atomicReference.compareAndSet(null, adapterCreator)) {
            if (atomicReference.get() != null && atomicReference.get() != null) {
                return;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Ai
    /* renamed from: zza */
    public Vp mo17zza() {
        switch (this.a) {
        }
        return (Vp) this.c;
    }

    @Override // com.google.android.gms.internal.ads.Y1
    public ArrayList zzc(long j) {
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        int i = 0;
        while (true) {
            List list = (List) this.b;
            if (i >= list.size()) {
                break;
            }
            int i2 = i + i;
            long[] jArr = (long[]) this.c;
            if (jArr[i2] <= j && j < jArr[i2 + 1]) {
                A2 a2 = (A2) list.get(i);
                Gg gg = a2.a;
                if (gg.e == -3.4028235E38f) {
                    arrayList2.add(a2);
                } else {
                    arrayList.add(gg);
                }
            }
            i++;
        }
        Collections.sort(arrayList2, new B2(1));
        for (int i3 = 0; i3 < arrayList2.size(); i3++) {
            Gg gg2 = ((A2) arrayList2.get(i3)).a;
            arrayList.add(new Gg(gg2.a, gg2.b, gg2.c, gg2.d, (-1) - i3, 1, gg2.g, gg2.h, gg2.i, gg2.l, gg2.m, gg2.j, gg2.k, gg2.n, gg2.o));
        }
        return arrayList;
    }

    public /* synthetic */ C2326lq(int i, Object obj, Object obj2, Object obj3, boolean z) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    public C2326lq(Context context, VersionInfoParcel versionInfoParcel, C2429o6 c2429o6, Fi fi) {
        this.a = 17;
        this.b = context;
        this.d = versionInfoParcel;
        this.c = c2429o6;
    }

    @Override // com.google.android.gms.internal.ads.Xh
    /* renamed from: b */
    public void mo16b(Object obj) {
        ((Xg) obj).v((BinderC1966dc) this.b, (String) this.c, (String) this.d);
    }

    @Override // com.google.android.gms.internal.ads.Y1
    public int zza() {
        return ((long[]) this.d).length;
    }

    public C2326lq(InterfaceC1671Ca interfaceC1671Ca) {
        this.a = 9;
        this.b = interfaceC1671Ca;
    }

    public C2326lq(C1689Fa c1689Fa, C1683Ea c1683Ea, InterfaceC1707Ia interfaceC1707Ia) {
        this.a = 13;
        this.c = c1689Fa;
        this.d = c1683Ea;
        this.b = interfaceC1707Ia;
    }

    public C2326lq(C1849aq c1849aq, Vp vp, String str) {
        this.a = 10;
        this.b = c1849aq;
        this.c = vp;
        this.d = str == null ? "com.google.ads.mediation.admob.AdMobAdapter" : str;
    }

    public C2326lq(C2326lq c2326lq, Qg qg, Xv xv) {
        this.a = 25;
        this.b = c2326lq;
        this.c = qg;
    }

    public C2326lq(C2326lq c2326lq, Xv xv) {
        this.a = 24;
        this.d = new C2147hi(25, (byte) 0);
        this.b = c2326lq;
        this.c = xv;
    }

    public /* synthetic */ C2326lq(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj2;
        this.c = obj3;
        this.d = obj;
    }

    public C2326lq(int i) {
        this.a = i;
        switch (i) {
            case 7:
                this.b = new ArrayList();
                this.c = new ArrayList();
                this.d = new ArrayList();
                break;
            case 27:
                this.c = new ArrayDeque();
                this.d = null;
                this.b = new ThreadPoolExecutor(1, 1, 1L, TimeUnit.SECONDS, new LinkedBlockingQueue());
                break;
            default:
                String str = Yo.a;
                this.b = new ExecutorC1859b(Executors.newSingleThreadExecutor(new ThreadFactoryC1733Mc("ExoPlayer:Loader:ProgressiveMediaPeriod")), new TD(21));
                break;
        }
    }

    public C2326lq(Context context, com.google.android.gms.ads.internal.client.Y y) {
        this.a = 0;
        this.d = new AtomicReference();
        this.b = context;
        this.c = y;
    }

    public C2326lq(Context context, Executor executor, Z3 z3, S4 s4) {
        this.a = 5;
        this.c = s4;
        this.d = z3;
        RunnableFutureC2161hw runnableFutureC2161hw = new RunnableFutureC2161hw(new A4(0, this, context));
        executor.execute(runnableFutureC2161hw);
        this.b = runnableFutureC2161hw;
    }

    public C2326lq(C1929cj c1929cj, Hk hk) {
        this.a = 23;
        this.b = c1929cj;
        Ln ln = new Ln(hk);
        this.c = ln;
        this.d = new Qn(ln, c1929cj.e);
    }

    public C2326lq(zzfej zzfejVar) {
        this.a = 26;
        this.b = new ConcurrentHashMap(zzfejVar.e);
        this.c = zzfejVar;
        this.d = new C2669tq();
    }

    public C2326lq(Lz lz, List list, Px px) throws GeneralSecurityException {
        this.a = 29;
        this.b = lz;
        this.c = list;
        this.d = px;
        if (Cx.a.a.get()) {
            HashSet hashSet = new HashSet();
            for (Kz kz : lz.B()) {
                if (!hashSet.contains(Integer.valueOf(kz.w()))) {
                    hashSet.add(Integer.valueOf(kz.w()));
                } else {
                    throw new GeneralSecurityException(AbstractC0147y.c(kz.w(), "KeyID ", " is duplicated in the keyset, and Tink is configured to reject such keysets with the flag validateKeysetsOnParsing."));
                }
            }
            if (!hashSet.contains(Integer.valueOf(lz.x()))) {
                throw new GeneralSecurityException("Primary key id not found in keyset, and Tink is configured to reject such keysets with the flag validateKeysetsOnParsing.");
            }
        }
    }

    public C2326lq(String str, int i) {
        this.a = i;
        switch (i) {
            case 28:
                Fp fp = new Fp(5);
                this.c = fp;
                this.d = fp;
                this.b = str;
                break;
            default:
                EF ef = new EF();
                ef.a("video/mp2t");
                ef.d(str);
                this.b = new C1832aG(ef);
                break;
        }
    }

    public C2326lq(ArrayList arrayList) {
        this.a = 2;
        this.b = Collections.unmodifiableList(new ArrayList(arrayList));
        int size = arrayList.size();
        this.c = new long[size + size];
        for (int i = 0; i < arrayList.size(); i++) {
            A2 a2 = (A2) arrayList.get(i);
            long[] jArr = (long[]) this.c;
            int i2 = i + i;
            jArr[i2] = a2.b;
            jArr[i2 + 1] = a2.c;
        }
        long[] jArr2 = (long[]) this.c;
        long[] jArrCopyOf = Arrays.copyOf(jArr2, jArr2.length);
        this.d = jArrCopyOf;
        Arrays.sort(jArrCopyOf);
    }

    public C2326lq(List list) {
        this.a = 4;
        this.b = list;
        this.c = new InterfaceC2380n0[list.size()];
        this.d = new androidx.navigation.internal.m(new Os(this, 4));
    }
}
