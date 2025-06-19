package com.google.android.gms.internal.ads;

import android.os.Handler;
import android.os.Looper;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.oF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2438oF extends TE {
    public static final C2640t3 r;
    public final NE[] k;
    public final ArrayList l;
    public final A9[] m;
    public final ArrayList n;
    public int o = -1;
    public long[][] p;
    public zzvq q;

    static {
        C2244ju c2244ju = AbstractC2330lu.b;
        Bu bu = Bu.e;
        List list = Collections.EMPTY_LIST;
        E2 e2 = E2.a;
        r = new C2640t3("MergingMediaSource", new I0(), null, new D1(), C2082g4.B);
    }

    public C2438oF(TD td, NE... neArr) {
        this.k = neArr;
        this.n = new ArrayList(Arrays.asList(neArr));
        this.l = new ArrayList(neArr.length);
        int i = 0;
        while (true) {
            int length = neArr.length;
            if (i >= length) {
                this.m = new A9[length];
                this.p = new long[0][];
                new HashMap();
                AbstractC1981ds.C(new Zt().isEmpty());
                return;
            }
            this.l.add(new ArrayList());
            i++;
        }
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final void a(InterfaceC2005eF interfaceC2005eF) {
        C2352mF c2352mF = (C2352mF) interfaceC2005eF;
        int i = 0;
        while (true) {
            NE[] neArr = this.k;
            if (i >= neArr.length) {
                return;
            }
            List list = (List) this.l.get(i);
            boolean z = c2352mF.b[i];
            InterfaceC2005eF[] interfaceC2005eFArr = c2352mF.a;
            InterfaceC2005eF interfaceC2005eF2 = z ? ((GF) interfaceC2005eFArr[i]).a : interfaceC2005eFArr[i];
            int i2 = 0;
            while (true) {
                if (i2 >= list.size()) {
                    break;
                }
                if (((C2395nF) list.get(i2)).b.equals(interfaceC2005eF2)) {
                    list.remove(i2);
                    break;
                }
                i2++;
            }
            neArr[i].a(c2352mF.b[i] ? ((GF) interfaceC2005eFArr[i]).a : interfaceC2005eFArr[i]);
            i++;
        }
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final InterfaceC2005eF b(C2093gF c2093gF, C1963dG c1963dG, long j) {
        NE[] neArr = this.k;
        int length = neArr.length;
        InterfaceC2005eF[] interfaceC2005eFArr = new InterfaceC2005eF[length];
        A9[] a9Arr = this.m;
        int iA = a9Arr[0].a(c2093gF.a);
        for (int i = 0; i < length; i++) {
            C2093gF c2093gFA = c2093gF.a(a9Arr[i].f(iA));
            interfaceC2005eFArr[i] = neArr[i].b(c2093gFA, c1963dG, j - this.p[iA][i]);
            ((List) this.l.get(i)).add(new C2395nF(c2093gFA, interfaceC2005eFArr[i]));
        }
        return new C2352mF(this.p[iA], interfaceC2005eFArr);
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final C2640t3 c() {
        NE[] neArr = this.k;
        return neArr.length > 0 ? neArr[0].c() : r;
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final void j(C2050fG c2050fG) {
        this.j = c2050fG;
        String str = Yo.a;
        Looper looperMyLooper = Looper.myLooper();
        AbstractC1795We.p(looperMyLooper);
        this.i = new Handler(looperMyLooper, null);
        int i = 0;
        while (true) {
            NE[] neArr = this.k;
            if (i >= neArr.length) {
                return;
            }
            t(Integer.valueOf(i), neArr[i]);
            i++;
        }
    }

    @Override // com.google.android.gms.internal.ads.TE, com.google.android.gms.internal.ads.NE
    public final void m() {
        super.m();
        Arrays.fill(this.m, (Object) null);
        this.o = -1;
        this.q = null;
        ArrayList arrayList = this.n;
        arrayList.clear();
        Collections.addAll(arrayList, this.k);
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final void p(C2640t3 c2640t3) {
        this.k[0].p(c2640t3);
    }

    @Override // com.google.android.gms.internal.ads.TE, com.google.android.gms.internal.ads.NE
    public final void r() throws zzvq {
        zzvq zzvqVar = this.q;
        if (zzvqVar != null) {
            throw zzvqVar;
        }
        super.r();
    }

    @Override // com.google.android.gms.internal.ads.TE
    public final void s(Integer num, NE ne, A9 a9) {
        int iB;
        if (this.q != null) {
            return;
        }
        if (this.o == -1) {
            iB = a9.b();
            this.o = iB;
        } else {
            int iB2 = a9.b();
            int i = this.o;
            if (iB2 != i) {
                this.q = new zzvq();
                return;
            }
            iB = i;
        }
        int length = this.p.length;
        A9[] a9Arr = this.m;
        if (length == 0) {
            this.p = (long[][]) Array.newInstance((Class<?>) Long.TYPE, iB, a9Arr.length);
        }
        ArrayList arrayList = this.n;
        arrayList.remove(ne);
        a9Arr[num.intValue()] = a9;
        if (arrayList.isEmpty()) {
            k(a9Arr[0]);
        }
    }

    @Override // com.google.android.gms.internal.ads.TE
    public final /* bridge */ /* synthetic */ C2093gF w(Integer num, C2093gF c2093gF) {
        int iIntValue = num.intValue();
        ArrayList arrayList = this.l;
        List list = (List) arrayList.get(iIntValue);
        for (int i = 0; i < list.size(); i++) {
            if (((C2395nF) list.get(i)).a.equals(c2093gF)) {
                return ((C2395nF) ((List) arrayList.get(0)).get(i)).a;
            }
        }
        return null;
    }
}
