package androidx.camera.camera2.internal;

import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: androidx.camera.camera2.internal.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class RunnableC0146x implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.data.repository.course.membership.c b;

    public /* synthetic */ RunnableC0146x(com.quizlet.data.repository.course.membership.c cVar, int i) {
        this.a = i;
        this.b = cVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                com.quizlet.data.repository.course.membership.c cVar = this.b;
                if (((C) ((com.quizlet.data.interactor.school.b) cVar.c).c).H == 8) {
                    ((C) ((com.quizlet.data.interactor.school.b) cVar.c).c).t("Camera onError timeout, reopen it.");
                    ((C) ((com.quizlet.data.interactor.school.b) cVar.c).c).F(7);
                    ((C) ((com.quizlet.data.interactor.school.b) cVar.c).c).h.b();
                    break;
                } else {
                    C c = (C) ((com.quizlet.data.interactor.school.b) cVar.c).c;
                    c.t("Camera skip reopen at state: ".concat(AbstractC0147y.l(c.H)));
                    break;
                }
            default:
                com.quizlet.data.repository.course.membership.c cVar2 = this.b;
                if (!((AtomicBoolean) cVar2.b).getAndSet(true)) {
                    ((C) ((com.quizlet.data.interactor.school.b) cVar2.c).c).c.execute(new RunnableC0146x(cVar2, 0));
                    break;
                }
                break;
        }
    }
}
