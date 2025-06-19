package com.quizlet.quizletandroid;

/* renamed from: com.quizlet.quizletandroid.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4625h implements dagger.android.a {
    public final /* synthetic */ int a;
    public final dagger.hilt.internal.a b;

    public /* synthetic */ C4625h(u uVar, int i) {
        this.a = i;
        this.b = uVar;
    }

    @Override // dagger.android.a
    public final dagger.android.b create(Object obj) {
        switch (this.a) {
            case 0:
                return new com.quizlet.data.interactor.achievements.f((u) this.b, 25);
            case 1:
                return new k((u) this.b, 0);
            case 2:
                return new com.google.firebase.crashlytics.internal.common.j((u) this.b, 25);
            case 3:
                return new com.quizlet.local.ormlite.models.term.b((u) this.b, 3);
            case 4:
                return new com.quizlet.data.repository.qclass.c((u) this.b);
            case 5:
                return new com.quizlet.data.repository.searchexplanations.c((u) this.b);
            default:
                return new com.onetrust.otpublishers.headless.UI.fragment.q((C4622e) this.b, 24);
        }
    }

    public C4625h(u uVar, C4624g c4624g, C4622e c4622e) {
        this.a = 6;
        this.b = c4622e;
    }
}
