package com.google.android.gms.internal.ads;

import androidx.appcompat.view.menu.RunnableC0069f;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class Sm extends AbstractBinderC2185ic implements InterfaceC2532qh {
    public BinderC2623sn a;
    public com.bumptech.glide.manager.p b;
    public com.quizlet.data.repository.progress.b c;

    @Override // com.google.android.gms.internal.ads.InterfaceC2226jc
    public final synchronized void D(com.google.android.gms.dynamic.a aVar) {
        BinderC2623sn binderC2623sn = this.a;
        if (binderC2623sn != null) {
            binderC2623sn.d.C0(null);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2226jc
    public final synchronized void G0(com.google.android.gms.dynamic.a aVar, zzbwj zzbwjVar) {
        BinderC2623sn binderC2623sn = this.a;
        if (binderC2623sn != null) {
            binderC2623sn.d.C0(zzbwjVar);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2226jc
    public final synchronized void H2(com.google.android.gms.dynamic.a aVar) {
        com.bumptech.glide.manager.p pVar = this.b;
        if (pVar != null) {
            synchronized (pVar) {
                ((C2313ld) pVar.c).c(null);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2226jc
    public final synchronized void L0(com.google.android.gms.dynamic.a aVar) {
        BinderC2623sn binderC2623sn = this.a;
        if (binderC2623sn != null) {
            binderC2623sn.c.j1(new C1927ch(7));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2226jc
    public final synchronized void M3(com.google.android.gms.dynamic.a aVar) {
        com.quizlet.data.repository.progress.b bVar = this.c;
        if (bVar != null) {
            Executor executor = ((C2323ln) bVar.d).c;
            C2880ym c2880ym = (C2880ym) bVar.c;
            Vp vp = (Vp) bVar.b;
            executor.execute(new RunnableC0069f(10, bVar, (C1849aq) bVar.a, vp, c2880ym, false));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2226jc
    public final synchronized void O2(com.google.android.gms.dynamic.a aVar) {
        BinderC2623sn binderC2623sn = this.a;
        if (binderC2623sn != null) {
            binderC2623sn.a.I3();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2226jc
    public final synchronized void R1() {
        BinderC2623sn binderC2623sn = this.a;
        if (binderC2623sn != null) {
            binderC2623sn.c.b();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2226jc
    public final synchronized void V1(com.google.android.gms.dynamic.a aVar) {
        BinderC2623sn binderC2623sn = this.a;
        if (binderC2623sn != null) {
            binderC2623sn.d.q();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2226jc
    public final synchronized void b2(com.google.android.gms.dynamic.a aVar, int i) {
        com.bumptech.glide.manager.p pVar = this.b;
        if (pVar != null) {
            pVar.h(i);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2226jc
    public final synchronized void c1() {
        com.quizlet.data.repository.progress.b bVar = this.c;
        if (bVar != null) {
            com.google.android.gms.ads.internal.util.client.i.h("Fail to initialize adapter ".concat(String.valueOf(((C2880ym) bVar.c).a)));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2532qh
    public final synchronized void f0(com.bumptech.glide.manager.p pVar) {
        this.b = pVar;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2226jc
    public final synchronized void t0(com.google.android.gms.dynamic.a aVar) {
        BinderC2623sn binderC2623sn = this.a;
        if (binderC2623sn != null) {
            binderC2623sn.t0(aVar);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2226jc
    public final synchronized void zze(com.google.android.gms.dynamic.a aVar) {
        BinderC2623sn binderC2623sn = this.a;
        if (binderC2623sn != null) {
            binderC2623sn.b.onAdClicked();
        }
    }
}
