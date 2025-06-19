package com.google.firebase.messaging;

import com.google.android.gms.cloudmessaging.CloudMessage;

/* loaded from: classes2.dex */
public final /* synthetic */ class i implements com.google.android.gms.tasks.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ FirebaseMessaging b;

    public /* synthetic */ i(FirebaseMessaging firebaseMessaging, int i) {
        this.a = i;
        this.b = firebaseMessaging;
    }

    @Override // com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        switch (this.a) {
            case 0:
                this.b.lambda$new$3((A) obj);
                break;
            case 1:
                this.b.lambda$setNotificationDelegationEnabled$6((Void) obj);
                break;
            default:
                this.b.lambda$handleProxiedNotificationData$5((CloudMessage) obj);
                break;
        }
    }
}
