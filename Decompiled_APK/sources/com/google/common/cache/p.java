package com.google.common.cache;

import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.Serializable;

/* loaded from: classes2.dex */
public final class p implements Serializable {
    public final I a;

    public p(C3912f c3912f) {
        this.a = new I(c3912f);
    }

    private void readObject(ObjectInputStream objectInputStream) throws InvalidObjectException {
        throw new InvalidObjectException("Use ManualSerializationProxy");
    }

    public final Object a(Object obj) {
        I i = this.a;
        i.getClass();
        int iE = i.e(obj);
        Object objH = i.g(iE).h(iE, obj);
        C3907a c3907a = i.q;
        if (objH == null) {
            c3907a.getClass();
            return objH;
        }
        c3907a.getClass();
        return objH;
    }

    public Object writeReplace() {
        return new q(this.a);
    }
}
