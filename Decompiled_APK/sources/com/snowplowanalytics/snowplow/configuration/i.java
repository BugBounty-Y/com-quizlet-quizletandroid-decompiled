package com.snowplowanalytics.snowplow.configuration;

import com.quizlet.quizletandroid.ui.profile.p;
import java.util.List;
import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public final class i implements a {
    public static final /* synthetic */ int n = 0;
    public String a;
    public i b;
    public Boolean c;
    public com.snowplowanalytics.snowplow.tracker.b d;
    public p e;
    public Boolean f;
    public Boolean g;
    public Boolean h;
    public Boolean i;
    public Boolean j;
    public Boolean k;
    public Boolean l;
    public Boolean m;

    public final String a() {
        String str = this.a;
        if (str != null) {
            return str;
        }
        i iVar = this.b;
        String strA = iVar != null ? iVar.a() : null;
        return strA == null ? "" : strA;
    }

    public final boolean b() {
        Boolean bool = this.g;
        if (bool != null) {
            return bool.booleanValue();
        }
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.b()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return com.snowplowanalytics.core.tracker.p.f;
    }

    public final boolean c() {
        Boolean bool = this.c;
        if (bool != null) {
            return bool.booleanValue();
        }
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.c()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return true;
    }

    public final boolean d() {
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.d()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return com.snowplowanalytics.core.tracker.p.d;
    }

    public final com.snowplowanalytics.snowplow.tracker.a e() {
        i iVar = this.b;
        com.snowplowanalytics.snowplow.tracker.a aVarE = iVar != null ? iVar.e() : null;
        if (aVarE != null) {
            return aVarE;
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return com.snowplowanalytics.snowplow.tracker.a.Mobile;
    }

    public final boolean f() {
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.f()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return false;
    }

    public final boolean g() {
        Boolean bool = this.m;
        if (bool != null) {
            return bool.booleanValue();
        }
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.g()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return com.snowplowanalytics.core.tracker.p.g;
    }

    public final boolean h() {
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.h()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return false;
    }

    public final boolean j() {
        Boolean bool = this.l;
        if (bool != null) {
            return bool.booleanValue();
        }
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.j()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return com.snowplowanalytics.core.tracker.p.k;
    }

    public final boolean k() {
        Boolean bool = this.k;
        if (bool != null) {
            return bool.booleanValue();
        }
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.k()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return com.snowplowanalytics.core.tracker.p.h;
    }

    public final com.snowplowanalytics.snowplow.tracker.b l() {
        com.snowplowanalytics.snowplow.tracker.b bVar = this.d;
        if (bVar != null) {
            return bVar;
        }
        i iVar = this.b;
        com.snowplowanalytics.snowplow.tracker.b bVarL = iVar != null ? iVar.l() : null;
        if (bVarL != null) {
            return bVarL;
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return com.snowplowanalytics.snowplow.tracker.b.OFF;
    }

    public final com.snowplowanalytics.snowplow.tracker.c m() {
        p pVar = this.e;
        if (pVar != null) {
            return pVar;
        }
        i iVar = this.b;
        if (iVar != null) {
            return iVar.m();
        }
        return null;
    }

    public final boolean n() {
        Boolean bool = this.h;
        if (bool != null) {
            return bool.booleanValue();
        }
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.n()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return com.snowplowanalytics.core.tracker.p.c;
    }

    public final List o() {
        i iVar = this.b;
        if (iVar != null) {
            return iVar.o();
        }
        return null;
    }

    public final com.snowplowanalytics.snowplow.tracker.d p() {
        i iVar = this.b;
        if (iVar != null) {
            return iVar.p();
        }
        return null;
    }

    public final boolean q() {
        Boolean bool = this.i;
        if (bool != null) {
            return bool.booleanValue();
        }
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.q()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return com.snowplowanalytics.core.tracker.p.e;
    }

    public final boolean s() {
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.s()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return com.snowplowanalytics.core.tracker.p.j;
    }

    public final boolean t() {
        Boolean bool = this.j;
        if (bool != null) {
            return bool.booleanValue();
        }
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.t()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return com.snowplowanalytics.core.tracker.p.i;
    }

    public final boolean u() {
        Boolean bool = this.f;
        if (bool != null) {
            return bool.booleanValue();
        }
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.u()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return com.snowplowanalytics.core.tracker.p.b;
    }

    public final String v() {
        i iVar = this.b;
        if (iVar != null) {
            return iVar.v();
        }
        return null;
    }

    public final boolean w() {
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.w()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = com.snowplowanalytics.core.tracker.p.a;
        return false;
    }

    public final boolean x() {
        i iVar = this.b;
        Boolean boolValueOf = iVar != null ? Boolean.valueOf(iVar.x()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        return false;
    }
}
