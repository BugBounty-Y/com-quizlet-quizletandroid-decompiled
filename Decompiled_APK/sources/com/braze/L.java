package com.braze;

import com.facebook.FacebookException;
import com.facebook.internal.InterfaceC1561p;
import com.google.android.gms.internal.mlkit_vision_common.G2;
import com.google.android.gms.tasks.Task;
import com.google.firebase.messaging.FirebaseMessaging;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.DataWrapper;
import java.util.List;

/* loaded from: classes.dex */
public final /* synthetic */ class L implements IBrazeEndpointProvider, InterfaceC1561p, com.google.android.gms.tasks.e, io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    public /* synthetic */ L(String str, int i) {
        this.a = i;
        this.b = str;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) obj;
        List responses = apiThreeWrapper.getResponses();
        return (responses == null || responses.size() <= 0 || ((ApiResponse) responses.get(0)).getDataWrapper() == null || ((DataWrapper) ((ApiResponse) responses.get(0)).getDataWrapper()).getAuthentication().getState().equals(this.b)) ? io.reactivex.rxjava3.core.p.f(apiThreeWrapper) : io.reactivex.rxjava3.core.p.d(new IllegalStateException("state does not match"));
    }

    @Override // com.facebook.internal.InterfaceC1561p
    public void c(boolean z) {
        String str = this.b;
        int i = FacebookException.a;
        if (z) {
            try {
                com.facebook.internal.instrument.errorreport.a aVar = new com.facebook.internal.instrument.errorreport.a(str);
                if ((aVar.b == null || aVar.c == null) ? false : true) {
                    G2.i(aVar.a, aVar.toString());
                }
            } catch (Exception unused) {
            }
        }
    }

    @Override // com.google.android.gms.tasks.e
    public Task g(Object obj) {
        switch (this.a) {
            case 2:
                return FirebaseMessaging.lambda$subscribeToTopic$10(this.b, (com.google.firebase.messaging.A) obj);
            default:
                return FirebaseMessaging.lambda$unsubscribeFromTopic$11(this.b, (com.google.firebase.messaging.A) obj);
        }
    }
}
