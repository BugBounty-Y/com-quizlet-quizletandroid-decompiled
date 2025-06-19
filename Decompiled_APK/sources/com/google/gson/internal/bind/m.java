package com.google.gson.internal.bind;

import com.google.gson.q;
import com.google.gson.r;
import com.google.gson.reflect.TypeToken;

/* loaded from: classes2.dex */
public final class m implements r {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ q c;

    public /* synthetic */ m(Object obj, q qVar, int i) {
        this.a = i;
        this.b = obj;
        this.c = qVar;
    }

    @Override // com.google.gson.r
    public final q b(com.google.gson.k kVar, TypeToken typeToken) {
        switch (this.a) {
            case 0:
                if (typeToken.a == ((Class) this.b)) {
                    return this.c;
                }
                return null;
            case 1:
                Class cls = (Class) this.b;
                Class<?> cls2 = typeToken.a;
                if (cls.isAssignableFrom(cls2)) {
                    return new b(this, cls2);
                }
                return null;
            default:
                if (typeToken.equals((TypeToken) this.b)) {
                    return this.c;
                }
                return null;
        }
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return "Factory[type=" + ((Class) this.b).getName() + ",adapter=" + this.c + "]";
            case 1:
                return "Factory[typeHierarchy=" + ((Class) this.b).getName() + ",adapter=" + this.c + "]";
            default:
                return super.toString();
        }
    }
}
