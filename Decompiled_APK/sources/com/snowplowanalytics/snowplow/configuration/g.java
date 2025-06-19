package com.snowplowanalytics.snowplow.configuration;

import com.snowplowanalytics.core.tracker.p;
import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public final class g implements a {
    public g a;
    public com.snowplowanalytics.snowplow.util.c b;
    public com.snowplowanalytics.snowplow.util.c c;

    public final com.snowplowanalytics.snowplow.util.c a() {
        com.snowplowanalytics.snowplow.util.c cVar = this.c;
        if (cVar != null) {
            return cVar;
        }
        g gVar = this.a;
        com.snowplowanalytics.snowplow.util.c cVarA = gVar != null ? gVar.a() : null;
        if (cVarA != null) {
            return cVarA;
        }
        TimeUnit timeUnit = p.a;
        return new com.snowplowanalytics.snowplow.util.c(1800L, TimeUnit.SECONDS);
    }

    public final boolean b() {
        g gVar = this.a;
        Boolean boolValueOf = gVar != null ? Boolean.valueOf(gVar.b()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        TimeUnit timeUnit = p.a;
        return false;
    }

    public final com.snowplowanalytics.snowplow.util.c c() {
        com.snowplowanalytics.snowplow.util.c cVar = this.b;
        if (cVar != null) {
            return cVar;
        }
        g gVar = this.a;
        com.snowplowanalytics.snowplow.util.c cVarC = gVar != null ? gVar.c() : null;
        if (cVarC != null) {
            return cVarC;
        }
        TimeUnit timeUnit = p.a;
        return new com.snowplowanalytics.snowplow.util.c(1800L, TimeUnit.SECONDS);
    }

    public final androidx.core.util.a d() {
        g gVar = this.a;
        if (gVar != null) {
            return gVar.d();
        }
        return null;
    }

    public final boolean e() {
        g gVar = this.a;
        Boolean boolValueOf = gVar != null ? Boolean.valueOf(gVar.e()) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        return false;
    }
}
