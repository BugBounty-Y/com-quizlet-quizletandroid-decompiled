package com.snowplowanalytics.core.statemachine;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public com.snowplowanalytics.snowplow.event.a a;
    public e b;
    public f c;
    public d d;

    public final synchronized d a() {
        d dVarE;
        try {
            if (this.d == null && this.c != null) {
                e eVar = this.b;
                d dVarA = eVar != null ? eVar.a() : null;
                com.snowplowanalytics.snowplow.event.a aVar = this.a;
                if (aVar != null) {
                    f fVar = this.c;
                    Intrinsics.d(fVar);
                    dVarE = fVar.e(aVar, dVarA);
                } else {
                    dVarE = null;
                }
                this.d = dVarE;
                this.a = null;
                this.b = null;
                this.c = null;
            }
        } catch (Throwable th) {
            throw th;
        }
        return this.d;
    }
}
