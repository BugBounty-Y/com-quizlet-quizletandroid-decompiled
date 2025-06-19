package com.braze.events.internal.dispatchmanager;

import androidx.compose.animation.d0;
import com.braze.models.o;
import com.braze.requests.n;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public static final a e = new a();
    public final b a;
    public final List b;
    public final o c;
    public final n d;

    public c(b commandType, List brazeEvents, o oVar, com.braze.requests.b bVar, int i) {
        brazeEvents = (i & 2) != 0 ? K.a : brazeEvents;
        oVar = (i & 4) != 0 ? null : oVar;
        bVar = (i & 8) != 0 ? null : bVar;
        Intrinsics.checkNotNullParameter(commandType, "commandType");
        Intrinsics.checkNotNullParameter(brazeEvents, "brazeEvents");
        this.a = commandType;
        this.b = brazeEvents;
        this.c = oVar;
        this.d = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && Intrinsics.b(this.b, cVar.b) && Intrinsics.b(this.c, cVar.c) && Intrinsics.b(this.d, cVar.d);
    }

    public final int hashCode() {
        int iF = d0.f(this.a.hashCode() * 31, 31, this.b);
        o oVar = this.c;
        int iHashCode = (iF + (oVar == null ? 0 : oVar.a.hashCode())) * 31;
        n nVar = this.d;
        return iHashCode + (nVar != null ? nVar.hashCode() : 0);
    }

    public final String toString() {
        return "DispatchCommandEvent(commandType=" + this.a + ", brazeEvents=" + this.b + ", sessionId=" + this.c + ", brazeRequest=" + this.d + ')';
    }
}
