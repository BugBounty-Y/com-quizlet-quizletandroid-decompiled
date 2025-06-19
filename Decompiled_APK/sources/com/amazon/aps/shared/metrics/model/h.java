package com.amazon.aps.shared.metrics.model;

/* loaded from: classes.dex */
public final class h extends i {
    public m d;

    public h(m mVar) {
        super(mVar, 0L, 6);
        this.d = mVar;
    }

    @Override // com.amazon.aps.shared.metrics.model.i
    public final m a() {
        return this.d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof h) && this.d == ((h) obj).d;
    }

    public final int hashCode() {
        m mVar = this.d;
        if (mVar == null) {
            return 0;
        }
        return mVar.hashCode();
    }

    public final String toString() {
        return "ApsMetricsPerfAdFetchEvent(result=" + this.d + ')';
    }
}
