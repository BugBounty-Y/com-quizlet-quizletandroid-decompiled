package com.android.billingclient.api;

import java.util.ArrayList;
import java.util.function.Consumer;

/* loaded from: classes.dex */
public final /* synthetic */ class r implements Consumer {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ r(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.util.function.Consumer
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                ArrayList arrayList = new ArrayList();
                ((com.quizlet.billing.manager.a) this.b).a((e) obj, arrayList);
                break;
            default:
                ((com.google.android.material.search.a) this.b).a((e) obj);
                break;
        }
    }
}
