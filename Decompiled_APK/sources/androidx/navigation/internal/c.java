package androidx.navigation.internal;

import android.os.Bundle;
import androidx.compose.ui.platform.C0978y0;
import androidx.lifecycle.C1247h;
import androidx.lifecycle.L;
import androidx.lifecycle.p0;
import androidx.lifecycle.s0;
import androidx.navigation.B;
import androidx.navigation.C1291m;
import androidx.navigation.C1296s;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import java.util.Arrays;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.u;

/* loaded from: classes.dex */
public final class c {
    public final C1291m a;
    public final B b;
    public final Bundle c;
    public androidx.lifecycle.B d;
    public final C1296s e;
    public final String f;
    public final Bundle g;
    public final androidx.savedstate.e h;
    public boolean i;
    public final L j;
    public androidx.lifecycle.B k;
    public final s0 l;
    public final u m;

    public c(C1291m owner) {
        Intrinsics.checkNotNullParameter(owner, "entry");
        this.a = owner;
        owner.getClass();
        this.b = owner.b;
        this.c = owner.c;
        this.d = owner.d;
        this.e = owner.e;
        this.f = owner.f;
        this.g = owner.g;
        Intrinsics.checkNotNullParameter(owner, "owner");
        this.h = new androidx.savedstate.e(new C0978y0(owner, new C1247h(owner, 4)));
        u uVarB = kotlin.l.b(new androidx.lifecycle.compose.f(2));
        this.j = new L(owner);
        this.k = androidx.lifecycle.B.b;
        this.l = (s0) uVarB.getValue();
        this.m = kotlin.l.b(new androidx.lifecycle.compose.f(3));
    }

    public final Bundle a() {
        Bundle from = this.c;
        if (from == null) {
            return null;
        }
        V.c();
        Bundle source = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(from, "from");
        source.putAll(from);
        return source;
    }

    public final void b() {
        if (!this.i) {
            androidx.savedstate.e eVar = this.h;
            eVar.a.d();
            this.i = true;
            if (this.e != null) {
                p0.d(this.a);
            }
            eVar.a(this.g);
        }
        int iOrdinal = this.d.ordinal();
        int iOrdinal2 = this.k.ordinal();
        L l = this.j;
        if (iOrdinal < iOrdinal2) {
            l.g(this.d);
        } else {
            l.g(this.k);
        }
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(K.a(this.a.getClass()).f());
        sb.append("(" + this.f + ')');
        sb.append(" destination=");
        sb.append(this.b);
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }
}
