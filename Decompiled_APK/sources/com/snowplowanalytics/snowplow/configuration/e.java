package com.snowplowanalytics.snowplow.configuration;

import java.util.EnumSet;
import java.util.Map;
import okhttp3.A;
import okhttp3.n;

/* loaded from: classes3.dex */
public final class e implements a {
    public e a;
    public String b;
    public com.snowplowanalytics.snowplow.network.c c;
    public com.snowplowanalytics.snowplow.network.g d;

    public final String a() {
        e eVar = this.a;
        if (eVar != null) {
            return eVar.a();
        }
        return null;
    }

    public final String b() {
        String str = this.b;
        if (str != null) {
            return str;
        }
        e eVar = this.a;
        if (eVar != null) {
            return eVar.b();
        }
        return null;
    }

    public final com.snowplowanalytics.snowplow.network.c c() {
        com.snowplowanalytics.snowplow.network.c cVar = this.c;
        if (cVar != null) {
            return cVar;
        }
        e eVar = this.a;
        com.snowplowanalytics.snowplow.network.c cVarC = eVar != null ? eVar.c() : null;
        if (cVarC != null) {
            return cVarC;
        }
        EnumSet enumSet = com.snowplowanalytics.core.emitter.b.a;
        return com.snowplowanalytics.snowplow.network.c.b;
    }

    public final com.snowplowanalytics.snowplow.network.d d() {
        e eVar = this.a;
        if (eVar != null) {
            return eVar.d();
        }
        return null;
    }

    public final A e() {
        e eVar = this.a;
        if (eVar != null) {
            return eVar.e();
        }
        return null;
    }

    public final n f() {
        e eVar = this.a;
        if (eVar != null) {
            return eVar.f();
        }
        return null;
    }

    public final com.snowplowanalytics.snowplow.network.g g() {
        com.snowplowanalytics.snowplow.network.g gVar = this.d;
        if (gVar != null) {
            return gVar;
        }
        e eVar = this.a;
        com.snowplowanalytics.snowplow.network.g gVarG = eVar != null ? eVar.g() : null;
        if (gVarG != null) {
            return gVarG;
        }
        EnumSet enumSet = com.snowplowanalytics.core.emitter.b.a;
        return com.snowplowanalytics.snowplow.network.g.b;
    }

    public final Map h() {
        e eVar = this.a;
        if (eVar != null) {
            return eVar.h();
        }
        return null;
    }

    public final Integer j() {
        e eVar = this.a;
        Integer numJ = eVar != null ? eVar.j() : null;
        if (numJ != null) {
            return numJ;
        }
        EnumSet enumSet = com.snowplowanalytics.core.emitter.b.a;
        return Integer.valueOf(com.snowplowanalytics.core.emitter.b.g);
    }
}
