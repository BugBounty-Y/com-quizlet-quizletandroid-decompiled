package com.google.gson.internal.bind;

import java.lang.reflect.Field;
import java.security.PrivilegedAction;

/* loaded from: classes2.dex */
public final class o implements PrivilegedAction {
    public final /* synthetic */ Field a;

    public o(Field field) {
        this.a = field;
    }

    @Override // java.security.PrivilegedAction
    public final Object run() throws SecurityException {
        this.a.setAccessible(true);
        return null;
    }
}
