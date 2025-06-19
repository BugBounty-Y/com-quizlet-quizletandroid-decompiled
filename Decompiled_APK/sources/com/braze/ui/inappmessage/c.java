package com.braze.ui.inappmessage;

import com.braze.events.BrazeUserChangeEvent;
import com.braze.events.IEventSubscriber;
import com.braze.events.InAppMessageEvent;
import com.braze.events.SdkDataWipeEvent;

/* loaded from: classes.dex */
public final /* synthetic */ class c implements IEventSubscriber {
    public final /* synthetic */ int a;
    public final /* synthetic */ BrazeInAppMessageManager b;

    public /* synthetic */ c(BrazeInAppMessageManager brazeInAppMessageManager, int i) {
        this.a = i;
        this.b = brazeInAppMessageManager;
    }

    @Override // com.braze.events.IEventSubscriber
    public final void trigger(Object obj) {
        switch (this.a) {
            case 0:
                BrazeInAppMessageManager.ensureSubscribedToInAppMessageEvents$lambda$5(this.b, (SdkDataWipeEvent) obj);
                break;
            case 1:
                BrazeInAppMessageManager.createBrazeUserChangeEventSubscriber$lambda$57(this.b, (BrazeUserChangeEvent) obj);
                break;
            default:
                BrazeInAppMessageManager.createInAppMessageEventSubscriber$lambda$53(this.b, (InAppMessageEvent) obj);
                break;
        }
    }
}
