package com.braze.dispatch;

import com.braze.managers.C1495h;
import com.braze.managers.C1496i;
import com.braze.managers.C1500m;
import com.braze.managers.C1501n;
import com.braze.managers.a0;
import com.braze.managers.r;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class j implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;

    public /* synthetic */ j(int i, long j) {
        this.a = i;
        this.b = j;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return f.c(this.b);
            case 1:
                return a0.a(this.b);
            case 2:
                return C1495h.a(this.b);
            case 3:
                return C1496i.c(this.b);
            case 4:
                return C1496i.a(this.b);
            case 5:
                return C1500m.b(this.b);
            case 6:
                return C1501n.a(this.b);
            case 7:
                return r.a(this.b);
            case 8:
                return com.braze.models.outgoing.event.a.b(this.b);
            case 9:
                return com.braze.triggers.managers.d.a(this.b);
            default:
                return com.braze.triggers.managers.f.a(this.b);
        }
    }
}
