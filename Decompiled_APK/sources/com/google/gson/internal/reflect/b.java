package com.google.gson.internal.reflect;

import com.google.gson.internal.g;
import java.lang.reflect.AccessibleObject;

/* loaded from: classes2.dex */
public abstract class b {
    public static final b a;

    static {
        a = g.a < 9 ? new a() : new c();
    }

    public abstract void a(AccessibleObject accessibleObject);
}
