package com.google.common.base;

import com.google.android.gms.internal.measurement.D1;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

/* loaded from: classes2.dex */
public final class m implements l, Serializable {
    public transient Object a = new Object();
    public final D1 b;
    public volatile transient boolean c;
    public transient Object d;

    public m(D1 d1) {
        this.b = d1;
    }

    private void readObject(ObjectInputStream objectInputStream) throws ClassNotFoundException, IOException {
        objectInputStream.defaultReadObject();
        this.a = new Object();
    }

    @Override // com.google.common.base.l
    public final Object get() {
        if (!this.c) {
            synchronized (this.a) {
                try {
                    if (!this.c) {
                        Object obj = this.b.get();
                        this.d = obj;
                        this.c = true;
                        return obj;
                    }
                } finally {
                }
            }
        }
        return this.d;
    }

    public final String toString() {
        return android.support.v4.media.session.a.s(new StringBuilder("Suppliers.memoize("), this.c ? android.support.v4.media.session.a.s(new StringBuilder("<supplier that returned "), this.d, SimpleComparison.GREATER_THAN_OPERATION) : this.b, ")");
    }
}
