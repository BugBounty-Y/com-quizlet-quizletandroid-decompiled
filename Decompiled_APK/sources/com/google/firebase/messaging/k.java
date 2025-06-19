package com.google.firebase.messaging;

/* loaded from: classes2.dex */
public final /* synthetic */ class k implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ FirebaseMessaging b;
    public final /* synthetic */ com.google.android.gms.tasks.f c;

    public /* synthetic */ k(FirebaseMessaging firebaseMessaging, com.google.android.gms.tasks.f fVar, int i) {
        this.a = i;
        this.b = firebaseMessaging;
        this.c = fVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.lambda$getToken$7(this.c);
                break;
            default:
                this.b.lambda$deleteToken$9(this.c);
                break;
        }
    }
}
