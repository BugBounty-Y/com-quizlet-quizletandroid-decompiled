package com.quizlet.quizletandroid;

/* loaded from: classes3.dex */
public final class l implements dagger.android.a {
    public final /* synthetic */ int a;
    public final u b;
    public final C4622e c;

    public /* synthetic */ l(u uVar, C4624g c4624g, C4622e c4622e, int i) {
        this.a = i;
        this.b = uVar;
        this.c = c4622e;
    }

    @Override // dagger.android.a
    public final dagger.android.b create(Object obj) {
        switch (this.a) {
            case 0:
                return new com.quizlet.data.interactor.school.b(24, this.b, this.c);
            case 1:
                return new com.quizlet.data.repository.activitycenter.b(24, this.b, this.c);
            default:
                return new com.quizlet.data.repository.explanations.myexplanations.a(this.b, false, this.c, 24);
        }
    }
}
