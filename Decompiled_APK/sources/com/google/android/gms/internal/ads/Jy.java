package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public abstract class Jy {
    public static final Ey a;
    public static final Ey b;
    public static final C2892yy c;

    static {
        try {
            com.quizlet.data.repository.studysetwithcreator.d dVar = new com.quizlet.data.repository.studysetwithcreator.d(4);
            dVar.f(32);
            dVar.g(16);
            Dy dy = Dy.b;
            dVar.d = dy;
            Cy cy = Cy.d;
            dVar.c = cy;
            a = dVar.h();
            try {
                com.quizlet.data.repository.studysetwithcreator.d dVar2 = new com.quizlet.data.repository.studysetwithcreator.d(4);
                dVar2.f(32);
                dVar2.g(32);
                dVar2.d = dy;
                dVar2.c = cy;
                dVar2.h();
                try {
                    com.quizlet.data.repository.studysetwithcreator.d dVar3 = new com.quizlet.data.repository.studysetwithcreator.d(4);
                    dVar3.f(64);
                    dVar3.g(32);
                    dVar3.d = dy;
                    Cy cy2 = Cy.f;
                    dVar3.c = cy2;
                    dVar3.h();
                    try {
                        com.quizlet.data.repository.studysetwithcreator.d dVar4 = new com.quizlet.data.repository.studysetwithcreator.d(4);
                        dVar4.f(64);
                        dVar4.g(64);
                        dVar4.d = dy;
                        dVar4.c = cy2;
                        b = dVar4.h();
                        try {
                            Iw iw = new Iw();
                            iw.b(32);
                            iw.d(16);
                            iw.a = C2332lw.o;
                            c = iw.i();
                        } catch (Exception e) {
                            throw new zzgot(e);
                        }
                    } catch (Exception e2) {
                        throw new zzgot(e2);
                    }
                } catch (Exception e3) {
                    throw new zzgot(e3);
                }
            } catch (Exception e4) {
                throw new zzgot(e4);
            }
        } catch (Exception e5) {
            throw new zzgot(e5);
        }
    }
}
