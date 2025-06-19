package com.google.android.gms.internal.ads;

import java.nio.charset.Charset;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.regex.Matcher;

/* renamed from: com.google.android.gms.internal.ads.rt, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2586rt implements InterfaceC2390nA, Bt, Pk, SF {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ C2586rt(RD rd, zzba zzbaVar) {
        this.a = 6;
        this.b = zzbaVar;
    }

    @Override // com.google.android.gms.internal.ads.SF
    public Bu a(int i, J9 j9, int[] iArr) {
        C2244ju c2244ju = AbstractC2330lu.b;
        AbstractC2543qs.g(4, "initialCapacity");
        Object[] objArrCopyOf = new Object[4];
        int i2 = 0;
        int i3 = 0;
        while (i2 < j9.a) {
            int i4 = i;
            J9 j92 = j9;
            MF mf = new MF(i4, j92, i2, (PF) this.b, iArr[i2]);
            int length = objArrCopyOf.length;
            int i5 = i3 + 1;
            int iH = AbstractC2027eu.h(length, i5);
            if (iH > length) {
                objArrCopyOf = Arrays.copyOf(objArrCopyOf, iH);
            }
            objArrCopyOf[i3] = mf;
            i2++;
            i3 = i5;
            i = i4;
            j9 = j92;
        }
        return AbstractC2330lu.m(i3, objArrCopyOf);
    }

    @Override // com.google.android.gms.internal.ads.Pk
    /* renamed from: b */
    public void mo10b(Object obj) {
        SD sd = (SD) obj;
        switch (this.a) {
            case 6:
                sd.m((zzba) this.b);
                break;
            default:
                sd.i((C1832aG) this.b);
                break;
        }
    }

    public void c(int i, Object obj, InterfaceC2562rB interfaceC2562rB) {
        HA ha = (HA) this.b;
        ha.Q(i, 3);
        interfaceC2562rB.e((AbstractC2647tA) obj, ha.b);
        ha.Q(i, 4);
    }

    @Override // com.google.android.gms.internal.ads.Bt
    public Object zza() {
        return (C1968de) this.b;
    }

    public /* synthetic */ C2586rt(RD rd, C1832aG c1832aG, RC rc) {
        this.a = 7;
        this.b = c1832aG;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2390nA
    public Object zza(String str) {
        String[] strArr = {"GmsCore_OpenSSL", "AndroidOpenSSL"};
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < 2; i++) {
            Provider provider = Security.getProvider(strArr[i]);
            if (provider != null) {
                arrayList.add(provider);
            }
        }
        Iterator it2 = arrayList.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            C2806wy c2806wy = (C2806wy) this.b;
            if (!zHasNext) {
                return c2806wy.i(str, null);
            }
            try {
                return c2806wy.i(str, (Provider) it2.next());
            } catch (Exception unused) {
            }
        }
    }

    public /* synthetic */ C2586rt(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public C2586rt(Matcher matcher) {
        this.a = 0;
        matcher.getClass();
        this.b = matcher;
    }

    public C2586rt(HA ha) {
        this.a = 3;
        Charset charset = WA.a;
        this.b = ha;
        ha.b = this;
    }
}
