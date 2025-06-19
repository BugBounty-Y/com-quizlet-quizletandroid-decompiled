package org.slf4j.helpers;

import java.io.ObjectStreamException;
import java.io.Serializable;

/* loaded from: classes3.dex */
public abstract class f implements org.slf4j.b, Serializable {
    public String a;

    @Override // org.slf4j.b
    public String getName() {
        return this.a;
    }

    public Object readResolve() throws ObjectStreamException {
        return org.slf4j.d.d(getName());
    }
}
