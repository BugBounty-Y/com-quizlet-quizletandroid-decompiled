package com.snowplowanalytics.snowplow.configuration;

import java.util.EnumSet;
import java.util.Map;

/* loaded from: classes3.dex */
public final class b implements a {
    public b a;

    public final com.snowplowanalytics.snowplow.emitter.a a() {
        b bVar = this.a;
        com.snowplowanalytics.snowplow.emitter.a aVarA = bVar != null ? bVar.a() : null;
        if (aVarA != null) {
            return aVarA;
        }
        EnumSet enumSet = com.snowplowanalytics.core.emitter.b.a;
        return com.snowplowanalytics.snowplow.emitter.a.Single;
    }

    public final long b() {
        b bVar = this.a;
        Long lValueOf = bVar != null ? Long.valueOf(bVar.b()) : null;
        if (lValueOf != null) {
            return lValueOf.longValue();
        }
        EnumSet enumSet = com.snowplowanalytics.core.emitter.b.a;
        return com.snowplowanalytics.core.emitter.b.e;
    }

    public final long c() {
        b bVar = this.a;
        Long lValueOf = bVar != null ? Long.valueOf(bVar.c()) : null;
        if (lValueOf != null) {
            return lValueOf.longValue();
        }
        EnumSet enumSet = com.snowplowanalytics.core.emitter.b.a;
        return com.snowplowanalytics.core.emitter.b.f;
    }

    public final Map d() {
        b bVar = this.a;
        if (bVar != null) {
            return bVar.d();
        }
        return null;
    }

    public final int e() {
        b bVar = this.a;
        Integer numValueOf = bVar != null ? Integer.valueOf(bVar.e()) : null;
        if (numValueOf != null) {
            return numValueOf.intValue();
        }
        EnumSet enumSet = com.snowplowanalytics.core.emitter.b.a;
        return com.snowplowanalytics.core.emitter.b.b;
    }

    public final androidx.work.impl.background.greedy.d f() {
        b bVar = this.a;
        if (bVar != null) {
            return bVar.f();
        }
        return null;
    }

    public final long g() {
        b bVar = this.a;
        kotlin.time.b bVar2 = bVar != null ? new kotlin.time.b(bVar.g()) : null;
        if (bVar2 != null) {
            return bVar2.a;
        }
        EnumSet enumSet = com.snowplowanalytics.core.emitter.b.a;
        return com.snowplowanalytics.core.emitter.b.k;
    }

    public final long h() {
        b bVar = this.a;
        Long lValueOf = bVar != null ? Long.valueOf(bVar.h()) : null;
        if (lValueOf != null) {
            return lValueOf.longValue();
        }
        EnumSet enumSet = com.snowplowanalytics.core.emitter.b.a;
        return com.snowplowanalytics.core.emitter.b.l;
    }

    public final void j() {
        b bVar = this.a;
        if (bVar != null) {
            bVar.j();
        }
    }

    public final boolean k() {
        b bVar = this.a;
        Boolean boolValueOf = bVar != null ? Boolean.valueOf(bVar.k()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        EnumSet enumSet = com.snowplowanalytics.core.emitter.b.a;
        return com.snowplowanalytics.core.emitter.b.i;
    }

    public final boolean l() {
        b bVar = this.a;
        Boolean boolValueOf = bVar != null ? Boolean.valueOf(bVar.l()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        EnumSet enumSet = com.snowplowanalytics.core.emitter.b.a;
        return false;
    }

    public final int m() {
        b bVar = this.a;
        Integer numValueOf = bVar != null ? Integer.valueOf(bVar.m()) : null;
        if (numValueOf != null) {
            return numValueOf.intValue();
        }
        EnumSet enumSet = com.snowplowanalytics.core.emitter.b.a;
        return com.snowplowanalytics.core.emitter.b.h;
    }

    public final boolean n() {
        b bVar = this.a;
        Boolean boolValueOf = bVar != null ? Boolean.valueOf(bVar.n()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        return false;
    }
}
