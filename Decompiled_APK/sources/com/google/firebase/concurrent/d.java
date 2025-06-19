package com.google.firebase.concurrent;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ e b;
    public final /* synthetic */ Runnable c;
    public final /* synthetic */ com.quizlet.data.repository.school.membership.a d;

    public /* synthetic */ d(e eVar, Runnable runnable, com.quizlet.data.repository.school.membership.a aVar, int i) {
        this.a = i;
        this.b = eVar;
        this.c = runnable;
        this.d = aVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                e eVar = this.b;
                final com.quizlet.data.repository.school.membership.a aVar = this.d;
                final Runnable runnable = this.c;
                final int i = 0;
                eVar.a.execute(new Runnable() { // from class: com.google.firebase.concurrent.b
                    @Override // java.lang.Runnable
                    public final void run() throws Exception {
                        switch (i) {
                            case 0:
                                try {
                                    runnable.run();
                                    return;
                                } catch (Exception e) {
                                    ((g) aVar.b).l(e);
                                    throw e;
                                }
                            case 1:
                                try {
                                    runnable.run();
                                    return;
                                } catch (Exception e2) {
                                    ((g) aVar.b).l(e2);
                                    return;
                                }
                            default:
                                Runnable runnable2 = runnable;
                                g gVar = (g) aVar.b;
                                try {
                                    runnable2.run();
                                    gVar.k(null);
                                    return;
                                } catch (Exception e3) {
                                    gVar.l(e3);
                                    return;
                                }
                        }
                    }
                });
                break;
            case 1:
                e eVar2 = this.b;
                final com.quizlet.data.repository.school.membership.a aVar2 = this.d;
                final Runnable runnable2 = this.c;
                final int i2 = 2;
                eVar2.a.execute(new Runnable() { // from class: com.google.firebase.concurrent.b
                    @Override // java.lang.Runnable
                    public final void run() throws Exception {
                        switch (i2) {
                            case 0:
                                try {
                                    runnable2.run();
                                    return;
                                } catch (Exception e) {
                                    ((g) aVar2.b).l(e);
                                    throw e;
                                }
                            case 1:
                                try {
                                    runnable2.run();
                                    return;
                                } catch (Exception e2) {
                                    ((g) aVar2.b).l(e2);
                                    return;
                                }
                            default:
                                Runnable runnable22 = runnable2;
                                g gVar = (g) aVar2.b;
                                try {
                                    runnable22.run();
                                    gVar.k(null);
                                    return;
                                } catch (Exception e3) {
                                    gVar.l(e3);
                                    return;
                                }
                        }
                    }
                });
                break;
            default:
                e eVar3 = this.b;
                final com.quizlet.data.repository.school.membership.a aVar3 = this.d;
                final Runnable runnable3 = this.c;
                final int i3 = 1;
                eVar3.a.execute(new Runnable() { // from class: com.google.firebase.concurrent.b
                    @Override // java.lang.Runnable
                    public final void run() throws Exception {
                        switch (i3) {
                            case 0:
                                try {
                                    runnable3.run();
                                    return;
                                } catch (Exception e) {
                                    ((g) aVar3.b).l(e);
                                    throw e;
                                }
                            case 1:
                                try {
                                    runnable3.run();
                                    return;
                                } catch (Exception e2) {
                                    ((g) aVar3.b).l(e2);
                                    return;
                                }
                            default:
                                Runnable runnable22 = runnable3;
                                g gVar = (g) aVar3.b;
                                try {
                                    runnable22.run();
                                    gVar.k(null);
                                    return;
                                } catch (Exception e3) {
                                    gVar.l(e3);
                                    return;
                                }
                        }
                    }
                });
                break;
        }
    }
}
