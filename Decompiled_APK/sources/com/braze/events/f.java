package com.braze.events;

import com.braze.events.internal.a0;
import com.braze.events.internal.e0;
import com.braze.events.internal.f0;
import com.braze.events.internal.g0;
import com.braze.events.internal.h0;
import com.braze.events.internal.l;
import com.braze.events.internal.m;
import com.braze.events.internal.n;
import com.braze.events.internal.w;
import com.braze.events.internal.y;
import com.braze.events.internal.z;

/* loaded from: classes.dex */
public final /* synthetic */ class f implements IEventSubscriber {
    public final /* synthetic */ int a;
    public final /* synthetic */ a b;

    public /* synthetic */ f(a aVar, int i) {
        this.a = i;
        this.b = aVar;
    }

    @Override // com.braze.events.IEventSubscriber
    public final void trigger(Object obj) {
        switch (this.a) {
            case 0:
                a.a(this.b, (com.braze.events.internal.g) obj);
                break;
            case 1:
                a.a(this.b, null, (Throwable) obj);
                break;
            case 2:
                a.a(this.b, (a0) obj);
                break;
            case 3:
                a.a(this.b, (n) obj);
                break;
            case 4:
                a.a(this.b, (f0) obj);
                break;
            case 5:
                a.a(this.b, (l) obj);
                break;
            case 6:
                a.a(this.b, (e0) obj);
                break;
            case 7:
                a.a(this.b, (y) obj);
                break;
            case 8:
                a.a(this.b, (m) obj);
                break;
            case 9:
                a.a(this.b, (w) obj);
                break;
            case 10:
                a.a(this.b, (com.braze.events.internal.a) obj);
                break;
            case 11:
                a.a(this.b, (com.braze.exceptions.b) obj);
                break;
            case 12:
                a.a(this.b, (com.braze.events.internal.f) obj);
                break;
            case 13:
                a.a(this.b, (com.braze.events.internal.d) obj);
                break;
            case 14:
                a.a(this.b, (com.braze.events.internal.e) obj);
                break;
            case 15:
                a.a(this.b, (z) obj);
                break;
            case 16:
                a.a(this.b, (h0) obj);
                break;
            case 17:
                a.a(this.b, (g0) obj);
                break;
            default:
                a.a(this.b, (com.braze.events.internal.i) obj);
                break;
        }
    }
}
