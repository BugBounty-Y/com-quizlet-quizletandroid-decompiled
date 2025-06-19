package androidx.constraintlayout.core;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class d {
    public final Object[] a;
    public int b;

    public d(int i) {
        if (i <= 0) {
            throw new IllegalArgumentException("The max pool size must be > 0");
        }
        this.a = new Object[i];
    }

    public Object a() {
        int i = this.b;
        if (i <= 0) {
            return null;
        }
        int i2 = i - 1;
        Object[] objArr = this.a;
        Object obj = objArr[i2];
        Intrinsics.e(obj, "null cannot be cast to non-null type T of androidx.core.util.Pools.SimplePool");
        objArr[i2] = null;
        this.b--;
        return obj;
    }

    public void b(b bVar) {
        int i = this.b;
        Object[] objArr = this.a;
        if (i < objArr.length) {
            objArr[i] = bVar;
            this.b = i + 1;
        }
    }

    public boolean c(Object instance) {
        Object[] objArr;
        boolean z;
        Intrinsics.checkNotNullParameter(instance, "instance");
        int i = this.b;
        int i2 = 0;
        while (true) {
            objArr = this.a;
            if (i2 >= i) {
                z = false;
                break;
            }
            if (objArr[i2] == instance) {
                z = true;
                break;
            }
            i2++;
        }
        if (z) {
            throw new IllegalStateException("Already in the pool!");
        }
        int i3 = this.b;
        if (i3 >= objArr.length) {
            return false;
        }
        objArr[i3] = instance;
        this.b = i3 + 1;
        return true;
    }

    public d() {
        this.a = new Object[256];
    }
}
