package com.google.android.gms.internal.ads;

import android.os.Bundle;
import java.util.List;

/* loaded from: classes2.dex */
public final /* synthetic */ class Oo implements Ev, InterfaceC2650tD {
    public boolean a;
    public boolean b;
    public final Object c;
    public final Object d;
    public Object e;
    public Object f;

    public /* synthetic */ Oo(Qo qo, String str, List list, Bundle bundle, boolean z, boolean z2) {
        this.c = qo;
        this.d = str;
        this.e = list;
        this.f = bundle;
        this.a = z;
        this.b = z2;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2650tD
    public C2040f6 a() {
        InterfaceC2650tD interfaceC2650tD = (InterfaceC2650tD) this.f;
        return interfaceC2650tD != null ? interfaceC2650tD.a() : ((QD) this.c).d;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2650tD
    public void b(C2040f6 c2040f6) {
        InterfaceC2650tD interfaceC2650tD = (InterfaceC2650tD) this.f;
        if (interfaceC2650tD != null) {
            interfaceC2650tD.b(c2040f6);
            c2040f6 = ((InterfaceC2650tD) this.f).a();
        }
        ((QD) this.c).b(c2040f6);
    }

    public void c(JE je) {
        InterfaceC2650tD interfaceC2650tD;
        InterfaceC2650tD interfaceC2650tDD0 = je.d0();
        if (interfaceC2650tDD0 == null || interfaceC2650tDD0 == (interfaceC2650tD = (InterfaceC2650tD) this.f)) {
            return;
        }
        if (interfaceC2650tD != null) {
            throw new zzik(2, new IllegalStateException("Multiple renderer media clocks enabled."), 1000);
        }
        this.f = interfaceC2650tDD0;
        this.e = je;
        ((C2651tE) interfaceC2650tDD0).b(((QD) this.c).d);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2650tD
    public boolean i() {
        if (this.a) {
            return false;
        }
        InterfaceC2650tD interfaceC2650tD = (InterfaceC2650tD) this.f;
        interfaceC2650tD.getClass();
        return interfaceC2650tD.i();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2650tD
    public long zza() {
        if (this.a) {
            return ((QD) this.c).zza();
        }
        InterfaceC2650tD interfaceC2650tD = (InterfaceC2650tD) this.f;
        interfaceC2650tD.getClass();
        return interfaceC2650tD.zza();
    }

    public Oo(C2436oD c2436oD) {
        this.d = c2436oD;
        QD qd = new QD();
        qd.d = C2040f6.d;
        this.c = qd;
        this.a = true;
    }

    /* JADX WARN: Removed duplicated region for block: B:71:0x0053 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    @Override // com.google.android.gms.internal.ads.Ev
    /* renamed from: zza, reason: collision with other method in class */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.common.util.concurrent.e mo19zza() {
        /*
            Method dump skipped, instructions count: 353
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Oo.mo19zza():com.google.common.util.concurrent.e");
    }
}
