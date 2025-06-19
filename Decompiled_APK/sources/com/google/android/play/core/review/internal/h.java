package com.google.android.play.core.review.internal;

import com.android.billingclient.api.u;

/* loaded from: classes2.dex */
public final class h extends e {
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    public /* synthetic */ h(Object obj, int i) {
        this.b = i;
        this.c = obj;
    }

    @Override // com.google.android.play.core.review.internal.e
    public final void a() {
        switch (this.b) {
            case 0:
                synchronized (((j) this.c).f) {
                    try {
                        if (((j) this.c).k.get() > 0 && ((j) this.c).k.decrementAndGet() > 0) {
                            ((j) this.c).b.a("Leaving the connection open for other ongoing calls.", new Object[0]);
                            return;
                        }
                        j jVar = (j) this.c;
                        if (jVar.m != null) {
                            jVar.b.a("Unbind from service.", new Object[0]);
                            j jVar2 = (j) this.c;
                            jVar2.a.unbindService(jVar2.l);
                            j jVar3 = (j) this.c;
                            jVar3.g = false;
                            jVar3.m = null;
                            jVar3.l = null;
                        }
                        ((j) this.c).c();
                        return;
                    } finally {
                    }
                }
            default:
                j jVar4 = (j) ((u) this.c).b;
                jVar4.b.a("unlinkToDeath", new Object[0]);
                ((b) jVar4.m).a.unlinkToDeath(jVar4.j, 0);
                jVar4.m = null;
                jVar4.g = false;
                return;
        }
    }
}
