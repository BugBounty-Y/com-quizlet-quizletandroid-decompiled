package com.google.common.base;

import com.google.android.gms.internal.measurement.D1;
import com.j256.ormlite.stmt.query.SimpleComparison;

/* loaded from: classes2.dex */
public final class n implements l {
    public static final com.facebook.appevents.k d = new com.facebook.appevents.k(23);
    public final Object a = new Object();
    public volatile l b;
    public Object c;

    public n(D1 d1) {
        this.b = d1;
    }

    @Override // com.google.common.base.l
    public final Object get() {
        l lVar = this.b;
        com.facebook.appevents.k kVar = d;
        if (lVar != kVar) {
            synchronized (this.a) {
                try {
                    if (this.b != kVar) {
                        Object obj = this.b.get();
                        this.c = obj;
                        this.b = kVar;
                        return obj;
                    }
                } finally {
                }
            }
        }
        return this.c;
    }

    public final String toString() {
        Object objS = this.b;
        StringBuilder sb = new StringBuilder("Suppliers.memoize(");
        if (objS == d) {
            objS = android.support.v4.media.session.a.s(new StringBuilder("<supplier that returned "), this.c, SimpleComparison.GREATER_THAN_OPERATION);
        }
        return android.support.v4.media.session.a.s(sb, objS, ")");
    }
}
