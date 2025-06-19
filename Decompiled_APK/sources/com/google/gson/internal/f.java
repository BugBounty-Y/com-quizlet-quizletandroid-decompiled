package com.google.gson.internal;

import com.google.gson.reflect.TypeToken;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes2.dex */
public final class f implements com.google.gson.r, Cloneable {
    public static final f c;
    public List a;
    public List b;

    static {
        f fVar = new f();
        List list = Collections.EMPTY_LIST;
        fVar.a = list;
        fVar.b = list;
        c = fVar;
    }

    public static boolean d(Class cls) {
        if (Enum.class.isAssignableFrom(cls) || (cls.getModifiers() & 8) != 0) {
            return false;
        }
        return cls.isAnonymousClass() || cls.isLocalClass();
    }

    @Override // com.google.gson.r
    public final com.google.gson.q b(com.google.gson.k kVar, TypeToken typeToken) {
        boolean z;
        boolean z2;
        boolean zD = d(typeToken.a);
        if (zD) {
            z = true;
        } else {
            c(true);
            z = false;
        }
        if (zD) {
            z2 = true;
        } else {
            c(false);
            z2 = false;
        }
        if (z || z2) {
            return new e(this, z2, z, kVar, typeToken);
        }
        return null;
    }

    public final void c(boolean z) {
        Iterator it2 = (z ? this.a : this.b).iterator();
        if (it2.hasNext()) {
            throw android.support.v4.media.session.a.d(it2);
        }
    }

    public final Object clone() {
        try {
            return (f) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }
}
