package com.squareup.moshi;

import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;

/* renamed from: com.squareup.moshi.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4847b extends H {
    public final /* synthetic */ int k;
    public final /* synthetic */ Class l;
    public final /* synthetic */ Executable m;

    public /* synthetic */ C4847b(Executable executable, Class cls, int i) {
        this.k = i;
        this.m = executable;
        this.l = cls;
    }

    @Override // com.squareup.moshi.H
    public final Object e() {
        switch (this.k) {
            case 0:
                return ((Constructor) this.m).newInstance(null);
            default:
                return ((Method) this.m).invoke(null, this.l, Object.class);
        }
    }

    public final String toString() {
        switch (this.k) {
        }
        return this.l.getName();
    }
}
