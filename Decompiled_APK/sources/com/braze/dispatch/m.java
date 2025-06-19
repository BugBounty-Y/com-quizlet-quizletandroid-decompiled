package com.braze.dispatch;

import com.braze.events.IEventSubscriber;
import com.braze.events.internal.c0;
import com.braze.events.internal.p;
import com.braze.events.internal.y;
import com.braze.managers.C1496i;
import com.braze.managers.k0;

/* loaded from: classes.dex */
public final /* synthetic */ class m implements IEventSubscriber {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ m(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.braze.events.IEventSubscriber
    public final void trigger(Object obj) {
        switch (this.a) {
            case 0:
                h.a((h) this.b, (com.braze.events.internal.dispatchmanager.c) obj);
                break;
            case 1:
                C1496i.a((C1496i) this.b, (y) obj);
                break;
            case 2:
                k0.a((k0) this.b, (p) obj);
                break;
            default:
                com.braze.triggers.managers.f.a((com.braze.triggers.managers.f) this.b, (c0) obj);
                break;
        }
    }
}
